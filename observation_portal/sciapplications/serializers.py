import os

from rest_framework import serializers
from PyPDF2 import PdfFileReader
from django.utils.translation import ugettext as _
from django.utils import timezone

from observation_portal.sciapplications.models import ScienceApplication, Call, TimeRequest, CoInvestigator


class CallSerializer(serializers.ModelSerializer):
    proposal_type_display = serializers.SerializerMethodField()
    instruments = serializers.SerializerMethodField()

    class Meta:
        model = Call
        fields = (
            'id', 'semester', 'eligible_semesters', 'proposal_type', 'proposal_type_display',
            'eligibility_short', 'eligibility', 'deadline', 'instruments'
        )

    def get_proposal_type_display(self, obj):
        return obj.get_proposal_type_display()

    def get_instruments(self, obj):
        return [
            {
                'id': instrument.id,
                'code': instrument.code,
                'name': instrument.display
            } for instrument in obj.instruments.all()
        ]


class CoInvestigatorSerializer(serializers.ModelSerializer):
    class Meta:
        model = CoInvestigator
        fields = ('first_name', 'last_name', 'institution', 'email')


class TimeRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = TimeRequest
        fields = ('semester', 'std_time', 'rr_time', 'tc_time', 'instrument')


class ScienceApplicationReadSerializer(serializers.ModelSerializer):
    call = CallSerializer()
    coinvestigator_set = CoInvestigatorSerializer(many=True)
    timerequest_set = TimeRequestSerializer(many=True)
    sca = serializers.SerializerMethodField()
    submitter = serializers.SerializerMethodField()

    class Meta:
        model = ScienceApplication
        fields = (
            'id', 'title', 'abstract', 'status', 'tac_rank', 'call', 'sca', 'submitted', 'pi',
            'pi_first_name', 'pi_last_name', 'pi_institution', 'submitter', 'timerequest_set',
            'coinvestigator_set', 'time_requested_by_telescope_name'
        )

    def get_sca(self, obj):
        return {
            'id': obj.sca.id,
            'name': obj.sca.name
        }

    def get_submitter(self, obj):
        return {
            'first_name': obj.submitter.first_name,
            'last_name': obj.submitter.last_name,
            'institution': obj.submitter.profile.institution
        }


def get_calls_queryset(request):
    if hasattr(request.user, 'sciencecollaborationallocation'):
        return Call.open_calls()
    else:
        return Call.open_calls().exclude(proposal_type=Call.COLLAB_PROPOSAL)


class OpenCallsPrimaryKeyRelatedField(serializers.PrimaryKeyRelatedField):
    def get_queryset(self):
        return get_calls_queryset(self.context['request'])


class ScienceApplicationCreateSerializer(serializers.ModelSerializer):
    title = serializers.CharField(required=True)
    status = serializers.CharField(required=True)
    call = OpenCallsPrimaryKeyRelatedField(required=True)
    coinvestigator_set = CoInvestigatorSerializer(many=True, required=False)
    timerequest_set = TimeRequestSerializer(many=True, required=False)
    pdf = serializers.FileField(required=False)

    class Meta:
        model = ScienceApplication
        fields = (
            'id', 'title', 'abstract', 'status', 'tac_rank', 'call', 'pi',
            'pi_first_name', 'pi_last_name', 'pi_institution', 'timerequest_set',
            'coinvestigator_set', 'pdf'
        )

    def validate_status(self, status):
        # Other application statuses are set via admin actions, these are the only valid ones
        # that can be set here.
        valid_statuses = (ScienceApplication.DRAFT, ScienceApplication.SUBMITTED)
        if status not in valid_statuses:
            raise serializers.ValidationError(_(f'Application status must be one of [{", ".join(valid_statuses)}]'))
        return status

    def validate_pdf(self, pdf):
        max_pages = 999

        extension = os.path.splitext(pdf.name)[1]
        if extension not in ['.pdf', '.PDF']:
            raise serializers.ValidationError(_('We can only accept PDF files.'))

        pdf_file = PdfFileReader(pdf.file)
        if pdf_file.getNumPages() > max_pages:
            raise serializers.ValidationError(_(f'PDF file cannot exceed {self.max_pages} pages'))

        return pdf

    def validate_abstract(self, abstract):
        abstract_word_limit = 500
        if len(abstract.split(' ')) > abstract_word_limit:
            raise serializers.ValidationError(_('Abstract is limited to 500 words.'))
        return abstract

    def validate(self, data):
        status = data['status']
        call = data['call']
        timerequest_set = data.get('timerequest_set', [])
        tac_rank = data.get('tac_rank', 0)

        for timerequest in timerequest_set:
            if timerequest['semester'].id not in call.eligible_semesters:
                raise serializers.ValidationError(_(
                    f'The semesters set for the time requests of this application must be one '
                    f'of {", ".join(call.eligible_semesters)}'
                ))

        if tac_rank > 0 and call.proposal_type != Call.COLLAB_PROPOSAL:
            raise serializers.ValidationError(_(
                f'{call.get_proposal_type_display()} applications are not allowed to set tac_rank'
            ))

        if status == ScienceApplication.SUBMITTED:
            required_fields = ['call', 'status', 'title', 'pi', 'pi_first_name', 'pi_last_name', 'pi_institution']
            if call.proposal_type == Call.DDT_PROPOSAL:
                required_fields.extend(['pdf'])
            elif call.proposal_type == Call.COLLAB_PROPOSAL:
                required_fields.extend(['abstract', 'tac_rank'])
            else:
                required_fields.extend(['abstract', 'pdf'])

            missing_fields = {}
            for field in required_fields:
                if not data.get(field):
                    missing_fields[field] = 'This field is required.'

            if missing_fields:
                raise serializers.ValidationError(_(missing_fields))

        return data

    def update(self, instance, validated_data):
        # TODO: Do this without needing to delete all existing time requests and coinvestigators
        timerequest_set = validated_data.pop('timerequest_set', [])
        coinvestigator_set = validated_data.pop('coinvestigator_set', [])

        for timerequest in instance.timerequest_set.all():
            timerequest.delete()
        for coinvestigator in instance.coinvestigator_set.all():
            coinvestigator.delete()

        for timerequest in timerequest_set:
            TimeRequest.objects.create(**timerequest, science_application=instance)
        for coinvestigator in coinvestigator_set:
            CoInvestigator.objects.create(**coinvestigator, science_application=instance)

        if validated_data['status'] == ScienceApplication.SUBMITTED:
            validated_data['submitted'] = timezone.now()

        instance.update(**validated_data)

        return instance

    def create(self, validated_data):
        timerequest_set = validated_data.pop('timerequest_set', [])
        coinvestigator_set = validated_data.pop('coinvestigator_set', [])
        # The pdf save path requires the sciapp instance id, so you must save the sciapp before saving the pdf.
        pdf = validated_data.pop('pdf', None)

        if validated_data['status'] == ScienceApplication.SUBMITTED:
            validated_data['submitted'] = timezone.now()

        sciapp = ScienceApplication.objects.create(**validated_data, submitter=self.context['request'].user)
        sciapp.pdf = pdf
        sciapp.save()

        for timerequest in timerequest_set:
            TimeRequest.objects.create(**timerequest, science_application=sciapp)
        for coinvestigator in coinvestigator_set:
            CoInvestigator.objects.create(**coinvestigator, science_application=sciapp)

        return sciapp