from rest_framework import serializers
from django.utils.translation import ugettext as _
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator
from json import JSONDecodeError
import logging
import json

from observation_portal.proposals.models import TimeAllocation, Membership
from observation_portal.requestgroups.models import (Request, Target, Window, RequestGroup, Location, Configuration,
    Constraints, InstrumentConfig, AcquisitionConfig, GuidingConfig, RegionOfInterest)
from observation_portal.requestgroups.models import DraftRequestGroup
from observation_portal.requestgroups.state_changes import debit_ipp_time, TimeAllocationError, validate_ipp
from observation_portal.requestgroups.target_helpers import TARGET_TYPE_HELPER_MAP
from observation_portal.common.configdb import configdb
from observation_portal.requestgroups.request_utils import MOLECULE_TYPE_DISPLAY
from observation_portal.requestgroups.duration_utils import (get_request_duration, get_request_duration_sum,
                                                             get_total_duration_dict, OVERHEAD_ALLOWANCE,
                                                             get_configuration_duration, get_num_exposures,
                                                             get_semester_in)
from datetime import timedelta, datetime
from observation_portal.common.rise_set_utils import get_rise_set_intervals


logger = logging.getLogger(__name__)


class CadenceSerializer(serializers.Serializer):
    start = serializers.DateTimeField()
    end = serializers.DateTimeField()
    period = serializers.FloatField(validators=[MinValueValidator(0.02)])
    jitter = serializers.FloatField(validators=[MinValueValidator(0.02)])

    def validate_end(self, value):
        if value < timezone.now():
            raise serializers.ValidationError('End time must be in the future')
        return value

    def validate(self, data):
        if data['start'] >= data['end']:
            msg = _("Cadence end '{}' cannot be earlier than cadence start '{}'.").format(data['start'], data['end'])
            raise serializers.ValidationError(msg)
        return data


class ConstraintsSerializer(serializers.ModelSerializer):
    max_airmass = serializers.FloatField(
        default=1.6, validators=[MinValueValidator(1.0), MaxValueValidator(25.0)]  # Duplicated in models.py
    )
    min_lunar_distance = serializers.FloatField(
        default=30.0, validators=[MinValueValidator(0.0), MaxValueValidator(180.0)]  # Duplicated in models.py
    )

    class Meta:
        model = Constraints
        exclude = Constraints.SERIALIZER_EXCLUDE


class RegionOfInterestSerializer(serializers.ModelSerializer):
    class Meta:
        model = RegionOfInterest
        exclude = RegionOfInterest.SERIALIZER_EXCLUDE

    def validate(self, data):
        return data


class InstrumentConfigSerializer(serializers.ModelSerializer):
    fill_window = serializers.BooleanField(required=False, write_only=True)
    rois = RegionOfInterestSerializer(many=True)

    class Meta:
        model = InstrumentConfig
        exclude = InstrumentConfig.SERIALIZER_EXCLUDE

    def validate(self, data):
        return data


class AcquisitionConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = AcquisitionConfig
        exclude = AcquisitionConfig.SERIALIZER_EXCLUDE

    def validate(self, data):
        return data


class GuidingConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = GuidingConfig
        exclude = GuidingConfig.SERIALIZER_EXCLUDE

    def validate(self, data):
        return data


class TargetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Target
        exclude = Target.SERIALIZER_EXCLUDE
        extra_kwargs = {
            'name': {'error_messages': {'blank': 'Please provide a name.'}}
        }

    def to_representation(self, instance):
        # Only return data for the specific target type
        data = super().to_representation(instance)
        target_helper = TARGET_TYPE_HELPER_MAP[data['type']](data)
        return {k: data.get(k) for k in target_helper.fields}

    def validate(self, data):
        target_helper = TARGET_TYPE_HELPER_MAP[data['type']](data)
        if target_helper.is_valid():
            data.update(target_helper.data)
        else:
            raise serializers.ValidationError(target_helper.error_dict)
        return data


class ConfigurationSerializer(serializers.ModelSerializer):
    constraints = ConstraintsSerializer()
    instrument_configs = InstrumentConfigSerializer(many=True)
    acquisition_config = AcquisitionConfigSerializer()
    guiding_config = GuidingConfigSerializer()
    target = TargetSerializer()

    class Meta:
        model = Configuration
        exclude = Configuration.SERIALIZER_EXCLUDE
        read_only_fields = ('priority',)

    def validate_instrument_name(self, value):
        if value and value not in configdb.get_active_instrument_types({}):
            raise serializers.ValidationError(
                _("Invalid instrument name {}. Valid instruments may include: {}").format(
                    value, ', '.join(configdb.get_active_instrument_types({}))
                )
            )
        return value

    def validate(self, data):
        # set special defaults if it is a spectrograph
        if configdb.is_spectrograph(data['instrument_name']):
            if 'state' not in data['guiding_config']:
                data['guiding_config']['state'] = 'ON'
            if 'state' not in data['acquisition_config']:
                data['acquisition_config']['state'] = 'ON'

            # if data['acquire_mode'] == 'BRIGHTEST' and not data.get('acquire_radius_arcsec'):
            #     raise serializers.ValidationError({'acquire_radius_arcsec': 'Acquire radius must be positive.'})

        # types_that_require_filter = ['expose', 'auto_focus', 'zero_pointing', 'standard', 'sky_flat']
        # types_that_require_slit = ['spectrum', 'arc', 'lamp_flat']
        # types_that_require_ag_mode_on = ['spectrum', 'nres_spectrum', 'nres_test', 'nres_expose']
        #
        # # Spectrum and NRES_SPECTRUM obs must have ag_mode 'ON'
        # if data['type'].lower() in types_that_require_ag_mode_on:
        #     if data['ag_mode'] is not 'ON':
        #         raise serializers.ValidationError({'ag_mode': _('Autoguiding must be on for {} observations.'.format(data['type']))})

        # Check if type is script, then args field is not blank
        # if data['type'].lower() == 'script':
        #     if 'args' not in data or not data['args']:
        #         raise serializers.ValidationError({'args': _('Script type molecules must supply script name as args')})

        # check that the filter is available in the instrument type specified
        # available_filters = configdb.get_filters(data['instrument_name'])
        # if configdb.is_spectrograph(data['instrument_name']):
        #     if (data['type'].lower() in types_that_require_slit
        #             and data.get('spectra_slit', '').lower() not in available_filters):
        #         raise serializers.ValidationError(
        #             {'spectra_slit': _("Invalid spectra slit {} for instrument {}. Valid slits are: {}").format(
        #                 data.get('spectra_slit', ''), data['instrument_name'], ", ".join(available_filters)
        #             )}
        #         )
        # elif data['type'].lower() in types_that_require_filter:
        #     if not data.get('filter'):
        #         raise serializers.ValidationError(
        #             {'filter': _("You must specify a filter for {} exposures.").format(
        #                 MOLECULE_TYPE_DISPLAY[data['type']]
        #             )}
        #         )
        #     elif data['filter'].lower() not in available_filters:
        #         raise serializers.ValidationError(
        #             {'filter': _("Invalid filter {} for instrument {}. Valid filters are: {}").format(
        #                 data['filter'], data['instrument_name'], ", ".join(available_filters)
        #             )}
        #         )

        if configdb.is_spectrograph(data['instrument_name']):
            for instrument_config in data['instrument_configs']:
                if 'rot_mode' not in instrument_config:
                    # TODO: Set default rot_mode for instrument here
                    pass

        if 'acceptability_threshold' not in data:
            # TODO: Set default acceptability threshold for the instrument class
            data['acceptability_threshold'] = 100

        # check that the binning is available for the instrument type specified
        if 'bin_x' not in data and 'bin_y' not in data:
            data['bin_x'] = configdb.get_default_binning(data['instrument_name'])
            data['bin_y'] = data['bin_x']
        elif 'bin_x' in data and 'bin_y' in data:
            available_binnings = configdb.get_binnings(data['instrument_name'])
            if data['bin_x'] not in available_binnings:
                msg = _("Invalid binning of {} for instrument {}. Valid binnings are: {}").format(
                    data['bin_x'], data['instrument_name'].upper(), ", ".join([str(b) for b in available_binnings])
                )
                raise serializers.ValidationError(msg)
        else:
            raise serializers.ValidationError(_("Missing one of bin_x or bin_y. Specify both or neither."))

        # check that the molecule type matches the instruemnt
        # imager_only_types = ['EXPOSE', 'SKY_FLAT', 'AUTO_FOCUS']
        # spec_only_types = ['SPECTRUM', 'ARC', 'LAMP_FLAT']
        # if configdb.is_spectrograph(data['instrument_name']) and data['type'] in imager_only_types:
        #     raise serializers.ValidationError(
        #         _('Invalid type {0} for a spectrograph.'.format(data['type']))
        #     )
        # if not configdb.is_spectrograph(data['instrument_name']) and data['type'] in spec_only_types:
        #     raise serializers.ValidationError(
        #         _('Invalid type {0} for an imager.'.format(data['type']))
        #     )

        return data


class LocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Location
        exclude = Location.SERIALIZER_EXCLUDE

    def validate(self, data):
        if 'observatory' in data and 'site' not in data:
            raise serializers.ValidationError(_("Must specify a site with an observatory."))
        if 'telescope' in data and 'observatory' not in data:
            raise serializers.ValidationError(_("Must specify an observatory with a telescope."))

        site_data_dict = {site['code']: site for site in configdb.get_site_data()}
        if 'site' in data:
            if data['site'] not in site_data_dict:
                msg = _('Site {} not valid. Valid choices: {}').format(data['site'], ', '.join(site_data_dict.keys()))
                raise serializers.ValidationError(msg)
            obs_set = site_data_dict[data['site']]['enclosure_set']
            obs_dict = {obs['code']: obs for obs in obs_set}
            if 'observatory' in data:
                if data['observatory'] not in obs_dict:
                    msg = _('Observatory {} not valid. Valid choices: {}').format(
                        data['observatory'],
                        ', '.join(obs_dict.keys())
                    )
                    raise serializers.ValidationError(msg)

                tel_set = obs_dict[data['observatory']]['telescope_set']
                tel_list = [tel['code'] for tel in tel_set]
                if 'telescope' in data and data['telescope'] not in tel_list:
                    msg = _('Telescope {} not valid. Valid choices: {}').format(data['telescope'], ', '.join(tel_list))
                    raise serializers.ValidationError(msg)

        return data

    def to_representation(self, instance):
        '''
        This method is overridden to remove blank fields from serialized output. We could put this into a subclassed
        ModelSerializer if we want it to apply to all our Serializers.
        :param instance:
        :return:
        '''
        rep = super().to_representation(instance)
        return {key: val for key, val in rep.items() if val}


class WindowSerializer(serializers.ModelSerializer):
    start = serializers.DateTimeField(required=False)

    class Meta:
        model = Window
        exclude = Window.SERIALIZER_EXCLUDE

    def validate(self, data):
        if 'start' not in data:
            data['start'] = timezone.now()
        if data['end'] <= data['start']:
            msg = _("Window end '{}' cannot be earlier than window start '{}'.").format(data['end'], data['start'])
            raise serializers.ValidationError(msg)

        if not get_semester_in(data['start'], data['end']):
            raise serializers.ValidationError('The observation window does not fit within any defined semester.')
        return data

    def validate_end(self, value):
        if value < timezone.now():
            raise serializers.ValidationError('Window end time must be in the future')
        return value


class RequestSerializer(serializers.ModelSerializer):
    location = LocationSerializer()
    configurations = ConfigurationSerializer(many=True)
    windows = WindowSerializer(many=True)
    cadence = CadenceSerializer(required=False, write_only=True)
    duration = serializers.ReadOnlyField()

    class Meta:
        model = Request
        read_only_fields = (
            'id', 'created', 'duration', 'state',
        )
        exclude = Request.SERIALIZER_EXCLUDE

    def validate_configurations(self, value):
        if not value:
            raise serializers.ValidationError(_('You must specify at least 1 configuration'))

        # Set the relative priority of molecules in order
        for i, configuration in enumerate(value):
            configuration['priority'] = i + 1

        # TODO: guiding config parameter for self-guiding rather than doing this check
        # # Validate autoguiders - empty string for default behavior, or match with instrument name for self guiding
        # for configuration in value:
        #     allowed_autoguiders = ['', str(configuration['instrument_name']).lower()]
        #     if 'ag_name' in configuration and str(configuration['ag_name']).lower() not in allowed_autoguiders:
        #         raise serializers.ValidationError(_('Molecule `ag_name` must be blank or same as `instrument_name`'))

        # TODO: Also restrict one fill window to either configuration or instrument_configuration level
        if any([conf.get('fill_window', False) for conf in value]):
            raise serializers.ValidationError(_('Only one configuration can have `fill_window` set'))

        return value

    def validate_windows(self, value):
        if not value:
            raise serializers.ValidationError(_('You must specify at least 1 window'))

        if len(set([get_semester_in(window['start'], window['end']) for window in value])) > 1:
            raise serializers.ValidationError(_('The observation windows must all be in the same semester'))

        return value

    def validate_cadence(self, value):
        if value:
            raise serializers.ValidationError(_('Please use the cadence endpoint to expand your cadence request'))
        return value

    def validate(self, data):
        # check if the instrument specified is allowed
        # TODO: Check if ALL instruments are available at a resource defined by location
        valid_instruments = configdb.get_active_instrument_types(data['location'])
        for configuration in data['configuration']:
            if configuration['instrument_name'] not in valid_instruments:
                msg = _("Invalid instrument name '{}' at site={}, obs={}, tel={}. \n").format(
                    configuration['instrument_name'], data['location'].get('site', 'Any'),
                    data['location'].get('observatory', 'Any'), data['location'].get('telescope', 'Any'))
                msg += _("Valid instruments include: ")
                for inst_name in valid_instruments:
                    msg += inst_name + ', '
                raise serializers.ValidationError(msg)

        # check that the requests window has enough rise_set visible time to accomodate the requests duration
        # if data.get('windows'):
        #     duration = get_request_duration(data)
        #     rise_set_intervals = get_rise_set_intervals(data)
        #     largest_interval = timedelta(seconds=0)
        #     for interval in rise_set_intervals:
        #         largest_interval = max((interval[1] - interval[0]), largest_interval)
        #
        #     for configuration in data['configuration']:
        #         if configuration.get('fill_window'):
        #             configuration_duration = get_configuration_duration(configuration_dict=configuration)
        #             num_exposures = get_num_exposures(
        #                 configuration, largest_interval - timedelta(seconds=duration - configuration_duration)
        #             )
        #             configuration['exposure_count'] = num_exposures
        #             duration = get_request_duration(data)
        #         # delete the fill window attribute, it is only used for this validation
        #         try:
        #             del configuration['fill_window']
        #         except KeyError:
        #             pass
        #     if largest_interval.total_seconds() <= 0:
        #         raise serializers.ValidationError(
        #             _(
        #                 'According to the constraints of the request, the target is never visible within the time '
        #                 'window. Check that the target is in the nighttime sky. Consider modifying the time '
        #                 'window or loosening the airmass or lunar separation constraints. If the target is '
        #                 'non sidereal, double check that the provided elements are correct.'
        #             )
        #         )
        #     if largest_interval.total_seconds() <= duration:
        #         raise serializers.ValidationError(
        #             (
        #                 'According to the constraints of the request, the target is visible for a maximum of {0:.2f} '
        #                 'hours within the time window. This is less than the duration of your request {1:.2f} hours. Consider '
        #                 'expanding the time window or loosening the airmass or lunar separation constraints.'
        #             ).format(
        #                 largest_interval.total_seconds() / 3600.0,
        #                 duration / 3600.0
        #             )
        #         )
        return data


class CadenceRequestSerializer(RequestSerializer):
    cadence = CadenceSerializer()
    windows = WindowSerializer(required=False, many=True)

    def validate_cadence(self, value):
        return value

    def validate_windows(self, value):
        if value:
            raise serializers.ValidationError(_('Cadence requests may not contain windows'))

        return value


class RequestGroupSerializer(serializers.ModelSerializer):
    requests = RequestSerializer(many=True)
    submitter = serializers.StringRelatedField(default=serializers.CurrentUserDefault())

    class Meta:
        model = RequestGroup
        fields = '__all__'
        read_only_fields = (
            'id', 'submitter', 'created', 'state', 'modified'
        )
        extra_kwargs = {
            'proposal': {'error_messages': {'null': 'Please provide a proposal.'}},
            'name': {'error_messages': {'blank': 'Please provide a title.'}}
        }

    @transaction.atomic
    def create(self, validated_data):
        request_data = validated_data.pop('requests')

        request_group = RequestGroup.objects.create(**validated_data)

        for r in request_data:
            windows_data = r.pop('windows')
            configurations_data = r.pop('configurations')
            location_data = r.pop('location')

            request = Request.objects.create(request_group=request_group, **r)
            Location.objects.create(request=request, **location_data)

            for window_data in windows_data:
                Window.objects.create(request=request, **window_data)
            for configuration_data in configurations_data:
                instrument_configs_data = configuration_data.pop('instrument_configs')
                acquisition_config_data = configuration_data.pop('acquisition_configs')
                guiding_config_data = configuration_data.pop('guiding_configs')
                target_data = configuration_data.pop('target')

                configuration = Configuration.objects.create(request=request, **configuration_data)

                AcquisitionConfig.objects.create(configuration=configuration, **acquisition_config_data)
                GuidingConfig.objects.create(configuration=configuration, **guiding_config_data)
                Target.objects.create(configuration=configuration, **target_data)

                for instrument_config_data in instrument_configs_data:
                    rois_data = instrument_config_data.pop('rois')
                    instrument_config = InstrumentConfig.objects.create(configuration=configuration,
                                                                        **instrument_config_data)
                    for roi_data in rois_data:
                        RegionOfInterest.objects.create(instrument_config=instrument_config, **roi_data)

        debit_ipp_time(request_group)

        logger.info('RequestGroup created', extra={'tags': {'user': request_group.submitter.username,
                                                           'tracking_num': request_group.id,
                                                           'name': request_group.name}})

        return request_group

    def validate(self, data):
        # check that the user belongs to the supplied proposal
        user = self.context['request'].user
        if data['proposal'] not in user.proposal_set.all():
            raise serializers.ValidationError(
                _('You do not belong to the proposal you are trying to submit')
            )

        # validation on the operator matching the number of requests
        if data['operator'] == 'SINGLE':
            if len(data['requests']) > 1:
                raise serializers.ValidationError(
                    _("'Single' type requestgroups must have exactly one child request.")
                )
        elif len(data['requests']) == 1:
            raise serializers.ValidationError(
                _("'{}' type requestgroups must have more than one child request.".format(data['operator'].title()))
            )

        # Check that the user has not exceeded the time limit on this membership
        membership = Membership.objects.get(user=user, proposal=data['proposal'])
        if membership.time_limit >= 0:
            duration = sum(d for i, d in get_request_duration_sum(data).items())
            time_to_be_used = user.profile.time_used_in_proposal(data['proposal']) + duration
            if membership.time_limit < time_to_be_used:
                raise serializers.ValidationError(
                    _('This request\'s duration will exceed the time limit set for your account on this proposal.')
                )

        try:
            total_duration_dict = get_total_duration_dict(data)
            for tak, duration in total_duration_dict.items():
                time_allocation = TimeAllocation.objects.get(
                    semester=tak.semester,
                    instrument_name=tak.instrument_name,
                    proposal=data['proposal'],
                )
                time_available = 0
                if data['observation_type'] == RequestGroup.NORMAL:
                    time_available = time_allocation.std_allocation - time_allocation.std_time_used
                elif data['observation_type'] == RequestGroup.RAPID_RESPONSE:
                    time_available = time_allocation.rr_allocation - time_allocation.rr_time_used
                    # For Rapid Response observations, check if the end time of the window is within
                    # six hours + the duration of the observation
                    for request in data['requests']:
                        windows = request.get('windows')
                        for window in windows:
                            if window.get('start') - timezone.now() > timedelta(seconds=0):
                                raise serializers.ValidationError(
                                    _("The Rapid Response observation window start time cannot be in the future.")
                                )
                            if window.get('end') - timezone.now() > timedelta(seconds=(duration + 21600)):
                                raise serializers.ValidationError(
                                    _("The Rapid Response observation window must be within the next six hours.")
                                )
                elif data['observation_type'] == RequestGroup.TIME_CRITICAL:
                    # Time critical time
                    time_available = time_allocation.tc_allocation - time_allocation.tc_time_used

                if time_available <= 0.0:
                    raise serializers.ValidationError(
                        _("Proposal {} does not have any time left allocated in semester {} on {} telescopes").format(
                            data['proposal'], tak.semester, tak.telescope_class)
                    )
                elif time_available * OVERHEAD_ALLOWANCE < (duration / 3600.0):
                    raise serializers.ValidationError(
                        _("Proposal {} does not have enough time allocated in semester {}").format(
                            data['proposal'], tak.semester)
                    )
            # validate the ipp debitting that will take place later
            validate_ipp(data, total_duration_dict)
        except ObjectDoesNotExist:
            raise serializers.ValidationError(
                _("You do not have sufficient time allocated on the instrument you're requesting for this proposal.")
            )
        except TimeAllocationError as e:
            raise serializers.ValidationError(repr(e))

        return data

    def validate_requests(self, value):
        if not value:
            raise serializers.ValidationError(_('You must specify at least 1 request'))
        return value


class DraftRequestGroupSerializer(serializers.ModelSerializer):
    author = serializers.SlugRelatedField(
        read_only=True,
        slug_field='username',
        default=serializers.CurrentUserDefault()
    )

    class Meta:
        model = DraftRequestGroup
        fields = '__all__'
        read_only_fields = ('author',)

    def validate(self, data):
        if data['proposal'] not in self.context['request'].user.proposal_set.all():
            raise serializers.ValidationError('You are not a member of that proposal')
        return data

    def validate_content(self, data):
        try:
            json.loads(data)
        except JSONDecodeError:
            raise serializers.ValidationError('Content must be valid JSON')
        return data