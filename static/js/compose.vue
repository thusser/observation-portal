<template>
  <b-container id="app" class="p-0">
    <b-form-row>
      <b-col>

        <!-- TODO Add in LCO terms -->

        <!-- TODO: If the same alert is brought up more than once, it will only display the 
        first time. This applies to all alerts, not just this one -->
        <customalert 
          v-for="alert in alerts"
          :key="alert.msg" 
          :alertclass="alert.class" 
          :dismissible="true"
        >
          {{ alert.msg }}
        </customalert>
      </b-col>
    </b-form-row>
    <b-tabs id="tabs" fill>
      <b-tab 
        :active="tab==1" 
        @click="tab=1"
      >
        <template slot="title">
          <i class="far fa-edit"></i> Form
        </template>
        <b-container class="p-0 mt-2">
          <b-form-row>
            <b-col class="m-0 p-0">            
              <requestgroup
                :errors="errors" 
                :duration_data="duration_data" 
                :requestgroup="requestgroup"
                @requestgroupupdate="requestgroupUpdated"
              />
            </b-col>
            <b-col
              cols="auto" 
              class="m-0 p-0"
            >
              <sidenav 
                :requestgroup="requestgroup" 
                :errors="errors" 
                :draftId="draftId"
                @savedraft="saveDraft($event.draftId)" 
                @submit="submit()"
                @clear="clear()"
              /> 
            </b-col>
          </b-form-row>
        </b-container>
      </b-tab>
      <b-tab 
        :active="tab==2"
        @click="tab=2"
      >
        <template slot="title">
          <i class="fas fa-code"></i> API View
        </template>
        <b-container class="p-0 mt-2">
          <b-form-row>
            <b-col class="bg-light rounded">
              <b-container class="p-4">
                <b-button 
                  :href="dataAsEncodedStr" 
                  download="apiview.json"
                  variant="info"
                  class="float-right"
                >
                  <i class="fa fa-download"></i> Download as JSON
                </b-button>
                <pre>{{ JSON.stringify(requestgroup, null, 4) }}</pre>
              </b-container>
            </b-col>
          </b-form-row>
        </b-container>
      </b-tab>
      <b-tab 
        :active="tab==3" 
        @click="tab=3"
      >
        <template slot="title">
          <i class="far fa-file-alt"></i> Drafts 
        </template>
        <b-container class="p-0 mt-2">
          <b-form-row>
            <b-col>
              <drafts 
                :tab="tab"
                @loaddraft="loadDraft"
              />
            </b-col>
          </b-form-row>
        </b-container>  
      </b-tab>
      <b-tab 
        :active="tab==4"
        @click="tab=4"
      >
        <template slot="title">
          <i class="fas fa-question"></i> How to use this page
        </template>
        <b-container class="p-0 mt-2">
          <b-form-row>
            <b-col class="my-3">
              <h2>Using the compose form</h2>
              <p>
                Use the form to describe the observation you would like carried out on the network.
                Sections marked with an exclamation mark <i class="fas fa-exclamation-triangle text-danger"></i> are incomplete or
                invalid. A complete section will be marked with a <i class="fa fa-check text-success"></i>. Only
                when all sections are marked complete can the observation be submitted.
              </p>
              <p>
                Some fields have blue question marks next to the field labels. Hovering over these question marks 
                will display more information about that field.
              </p>
              <p>
                Each section may be collapsed for a more compact view. Use the <i class="fa fa-window-minimize text-info"></i>
                and <i class="fa fa-window-maximize text-info"></i> buttons to control the state of the window.
              </p>
              <p>
                Some sections may be copied using the <i class="fa fa-copy text-success"></i> button. This will duplicate
                the section and add it to your observation request. Certain sections can also be removed using the
                <i class="fa fa-trash text-danger"></i> button. This button is only displayed if that section is eligible for removal.
              </p>
              <h2>Using the API view</h2>
              <p>
                This is what your request looks like in JSON format.
              </p>
              <p>
                This code can be used to submit this observation through the API.
                Using the API allows you to generate and submit observations for scheduling using
                programming languages like python.
              </p>
              <p>
                For more information see the
                <a target="_blank" href="https://developers.lco.global/#observations">API Documentation</a>.
              </p>
              <h2>Loading and saving drafts</h2>
              <p>
                Use the <i class="fa fa-save text-info"></i> button at any time to save an observation 
                request as a draft. Saved drafts can be loaded and managed from the Drafts tab. You will see 
                drafts saved by other members of your proposal as well as your own.
              </p>
            </b-col>
          </b-form-row>
        </b-container>
      </b-tab>
    </b-tabs>
  </b-container>
</template>
<script>
  import moment from 'moment';
  import _ from 'lodash';
  import $ from 'jquery';
  import Vue from 'vue';

  import requestgroup from './components/requestgroup.vue';
  import drafts from './components/drafts.vue';
  import sidenav from './components/sidenav.vue';
  import customalert from './components/util/customalert.vue';
  import { datetimeFormat } from './utils.js';

  export default {
    name: 'app',
    components: {
      requestgroup, 
      drafts, 
      sidenav, 
      customalert
    },
    data: function() {
      return {
        tab: 1,
        draftId: -1,
        requestgroup: {
          name: '',
          proposal: '',
          ipp_value: 1.05,
          operator: 'SINGLE',
          observation_type: 'NORMAL',
          requests: [{
            acceptability_threshold: '',
            configurations: [{
              type: 'EXPOSE',
              instrument_type: '',
              instrument_configs: [{
                bin_x: '',
                bin_y: '',
                exposure_count: 1,
                exposure_time: '',
                mode: '',
                rotator_mode: '',
                extra_params: {
                  defocus: 0
                },
                optical_elements: {}
              }],
              acquisition_config: {
                mode: 'OFF',
                extra_params: {
                  acquire_radius: null
                }
              },
              guiding_config: {
                mode: 'ON',
                optional: true,
                extra_params: {}
              },
              target: {
                name: '',
                type: 'ICRS',
                ra: '',
                dec: '',
                proper_motion_ra: 0.0,
                proper_motion_dec: 0.0,
                epoch: 2000,
                parallax: 0,
              },
              constraints: {
                max_airmass: 1.6,
                min_lunar_distance: 30.0
              }
            }],
            windows: [{
              start: moment.utc().format(datetimeFormat),
              end: moment.utc().add(1, 'days').format(datetimeFormat)
            }],
            location: {
              telescope_class: ''
            }
          }]
        },
        errors: {},
        duration_data: {},
        alerts: [],
      };
    },
    computed: {
      dataAsEncodedStr: function() {
        return 'data:application/json;charset=utf-8,' +  encodeURIComponent(JSON.stringify(this.requestgroup));
      }
    },
    methods: {
      validate: _.debounce(function() {
        let that = this;
        $.ajax({
          type: 'POST',
          url: '/api/requestgroups/validate/',
          data: JSON.stringify(that.requestgroup),
          contentType: 'application/json',
          success: function(data) {
            that.errors = data.errors;
            that.duration_data = data.request_durations;
          }
        });
      }, 200),
      submit: function() {
        let duration = moment.duration(this.duration_data.duration, 'seconds');
        let duration_string = '';
        if (duration.days() > 0) {
            duration_string = duration.days() + ' days, ' + duration_string;
        } 
        if (duration.hours() > 0) {
          duration_string += duration.hours() + ' hours, ';
        }
        duration_string += duration.minutes() + ' minutes, ' + duration.seconds() + ' seconds';
        if (confirm('The request will take approximately ' + duration_string + ' of telescope time. Are you sure you want to submit the request?')) {
          let that = this;
          $.ajax({
            type: 'POST',
            url: '/api/requestgroups/',
            data: JSON.stringify(that.requestgroup),
            contentType: 'application/json',
            success: function(data) {
              window.location = '/requestgroups/' + data.id;
            }
          });
        }
      },
      requestgroupUpdated: function() {
        console.log('requestgroup updated');
        this.validate();
      },
      saveDraft: function(id) {
        // Clear out alerts first so that only current alerts are displayed
        _.remove(this.alerts);
        if (!this.requestgroup.name || !this.requestgroup.proposal) {
          this.alerts.push({class: 'danger', msg: 'Please give your draft a title and proposal'});
          return;
        }
        let url = '/api/drafts/';
        let method = 'POST';
        if (id > -1) {
          url += id + '/';
          method = 'PUT';
        }
        let that = this;
        $.ajax({
          type: method,
          url: url,
          data: JSON.stringify({
            proposal: that.requestgroup.proposal,
            title: that.requestgroup.name,
            content: JSON.stringify(that.requestgroup)
          }),
          contentType: 'application/json',
        }).done(function(data) {
          that.draftId = data.id;
          that.alerts.push({class: 'success', msg: 'Draft id: ' + data.id + ' saved successfully'});
          console.log('Draft saved ' + that.draftId);
        }).fail(function(data) {
          for (let error in data.responseJSON.non_field_errors) {
            that.alerts.push({class: 'danger', msg: data.responseJSON.non_field_errors[error]});
          }
        });
      },
      loadDraft: function(id) {
        this.draftId = id;
        this.tab = 1;
        let that = this;
        $.getJSON('/api/drafts/' + id + '/', function(data) {
          that.requestgroup = {};
          Vue.nextTick(function() {
            that.requestgroup = JSON.parse(data.content);
          });
          that.validate();
        });
      },
      clear: function() {
        if (confirm('Clear the form?')) {
          window.location.reload();
        }
      }
    }
  };
</script>
