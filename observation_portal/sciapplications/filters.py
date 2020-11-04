import django_filters

from observation_portal.sciapplications.models import ScienceApplication, Call


class ScienceApplicationFilter(django_filters.FilterSet):
    status = django_filters.ChoiceFilter(
        choices=ScienceApplication.STATUS_CHOICES
    )
    exclude_status = django_filters.ChoiceFilter(
        choices=ScienceApplication.STATUS_CHOICES, exclude=True, field_name='status'
    )
    proposal_type = django_filters.ChoiceFilter(choices=Call.PROPOSAL_TYPE_CHOICES, field_name='call__proposal_type')
    exclude_proposal_type = django_filters.ChoiceFilter(
        choices=Call.PROPOSAL_TYPE_CHOICES, exclude=True, field_name='call__proposal_type'
    )
    only_authored = django_filters.BooleanFilter(method='filter_only_authored')

    class Meta:
        model = ScienceApplication
        fields = ('call', 'status', 'exclude_status', 'proposal_type', 'exclude_proposal_type', 'only_authored')

    def filter_only_authored(self, queryset, name, value):
        if value:
            return queryset.filter(submitter=self.request.user)
        else:
            return queryset
