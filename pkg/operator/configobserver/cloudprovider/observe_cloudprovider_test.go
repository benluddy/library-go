package cloudprovider

import (
	"testing"

	"github.com/openshift/library-go/pkg/operator/configobserver/featuregates"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	corelisterv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	configv1 "github.com/openshift/api/config/v1"
	configlistersv1 "github.com/openshift/client-go/config/listers/config/v1"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/resourcesynccontroller"
)

type FakeResourceSyncer struct{}

func (fakeSyncer *FakeResourceSyncer) SyncConfigMap(destination, source resourcesynccontroller.ResourceLocation) error {
	return nil
}

func (fakeSyncer *FakeResourceSyncer) SyncSecret(destination, source resourcesynccontroller.ResourceLocation) error {
	return nil
}

type FakeConfigMapLister struct{}

func (fakeCMLister *FakeConfigMapLister) ConfigMaps(ns string) corelisterv1.ConfigMapNamespaceLister {
	return fakeCMLister
}

func (fakeCMLister *FakeConfigMapLister) List(selector labels.Selector) ([]*corev1.ConfigMap, error) {
	return nil, nil
}

func (fakeCMLister *FakeConfigMapLister) Get(cm string) (*corev1.ConfigMap, error) {
	return nil, errors.NewNotFound(schema.GroupResource{}, "")
}

type FakeInfrastructureLister struct {
	InfrastructureLister_ configlistersv1.InfrastructureLister
	ResourceSync          resourcesynccontroller.ResourceSyncer
	PreRunCachesSynced    []cache.InformerSynced
	ConfigMapLister_      corelisterv1.ConfigMapLister
}

func (l FakeInfrastructureLister) ResourceSyncer() resourcesynccontroller.ResourceSyncer {
	return l.ResourceSync
}

func (l FakeInfrastructureLister) InfrastructureLister() configlistersv1.InfrastructureLister {
	return l.InfrastructureLister_
}

func (l FakeInfrastructureLister) PreRunHasSynced() []cache.InformerSynced {
	return l.PreRunCachesSynced
}

func (l FakeInfrastructureLister) ConfigMapLister() corelisterv1.ConfigMapLister {
	return l.ConfigMapLister_
}

func TestObserveCloudProviderNames(t *testing.T) {
	cases := []struct {
		name                      string
		infrastructureStatus      configv1.InfrastructureStatus
		featureGateAccessor       featuregates.FeatureGateAccess
		skipCloudProviderExternal bool
		expected                  string
		cloudProviderCount        int
		expectErrors              bool
	}{{
		name: "AWS platform set for external configuration (skip external for kas-o)",
		infrastructureStatus: configv1.InfrastructureStatus{
			Platform: configv1.AWSPlatformType,
			PlatformStatus: &configv1.PlatformStatus{
				Type: configv1.AWSPlatformType,
			},
		},
		skipCloudProviderExternal: true,
		expected:                  "",
		cloudProviderCount:        0,
	}, {
		name: "AWS platform",
		infrastructureStatus: configv1.InfrastructureStatus{
			Platform: configv1.AWSPlatformType,
			PlatformStatus: &configv1.PlatformStatus{
				Type: configv1.AWSPlatformType,
			},
		},
		expected:           "external",
		cloudProviderCount: 0,
	}, {
		name: "AlibabaCloud Platform",
		infrastructureStatus: configv1.InfrastructureStatus{
			Platform: configv1.AlibabaCloudPlatformType,
			PlatformStatus: &configv1.PlatformStatus{
				Type: configv1.AlibabaCloudPlatformType,
			},
		},
		expected:           "external",
		cloudProviderCount: 0,
	}, {
		name: "Nutanix Platform",
		infrastructureStatus: configv1.InfrastructureStatus{
			Platform: configv1.NutanixPlatformType,
			PlatformStatus: &configv1.PlatformStatus{
				Type: configv1.NutanixPlatformType,
			},
		},
		expected:           "external",
		cloudProviderCount: 0,
	}, {
		name: "Azure platform",
		infrastructureStatus: configv1.InfrastructureStatus{
			Platform: configv1.AzurePlatformType,
			PlatformStatus: &configv1.PlatformStatus{
				Type: configv1.AzurePlatformType,
			},
		},
		expected:           "external",
		cloudProviderCount: 0,
	}, {
		name: "Azure Stack Hub defaulting to external configuration",
		infrastructureStatus: configv1.InfrastructureStatus{
			Platform: configv1.AzurePlatformType,
			PlatformStatus: &configv1.PlatformStatus{
				Type: configv1.AzurePlatformType,
				Azure: &configv1.AzurePlatformStatus{
					CloudName: configv1.AzureStackCloud,
				},
			},
		},
		expected:           "external",
		cloudProviderCount: 0,
	}, {
		name: "BareMetal platform",
		infrastructureStatus: configv1.InfrastructureStatus{
			Platform: configv1.BareMetalPlatformType,
			PlatformStatus: &configv1.PlatformStatus{
				Type: configv1.BareMetalPlatformType,
			},
		},
		cloudProviderCount: 0,
	}, {
		name: "LibVirt platform",
		infrastructureStatus: configv1.InfrastructureStatus{
			Platform: configv1.LibvirtPlatformType,
			PlatformStatus: &configv1.PlatformStatus{
				Type: configv1.LibvirtPlatformType,
			},
		},
		cloudProviderCount: 0,
	}, {
		name: "OpenStack platform",
		infrastructureStatus: configv1.InfrastructureStatus{
			Platform: configv1.OpenStackPlatformType,
			PlatformStatus: &configv1.PlatformStatus{
				Type: configv1.OpenStackPlatformType,
			},
		},
		expected:           "external",
		cloudProviderCount: 0,
	}, {
		name: "GCP platform",
		infrastructureStatus: configv1.InfrastructureStatus{
			Platform: configv1.GCPPlatformType,
			PlatformStatus: &configv1.PlatformStatus{
				Type: configv1.GCPPlatformType,
			},
		},
		expected:           "external",
		cloudProviderCount: 0,
	}, {
		name: "IBM Cloud platform",
		infrastructureStatus: configv1.InfrastructureStatus{
			Platform: configv1.IBMCloudPlatformType,
			PlatformStatus: &configv1.PlatformStatus{
				Type: configv1.IBMCloudPlatformType,
			},
		},
		expected:           "external",
		cloudProviderCount: 0,
	}, {
		name: "Power VS platform",
		infrastructureStatus: configv1.InfrastructureStatus{
			Platform: configv1.PowerVSPlatformType,
			PlatformStatus: &configv1.PlatformStatus{
				Type: configv1.PowerVSPlatformType,
			},
		},
		expected:           "external",
		cloudProviderCount: 0,
	}, {
		name: "Kubevirt platform",
		infrastructureStatus: configv1.InfrastructureStatus{
			Platform: configv1.KubevirtPlatformType,
			PlatformStatus: &configv1.PlatformStatus{
				Type: configv1.KubevirtPlatformType,
			},
		},
		expected:           "external",
		cloudProviderCount: 0,
	}, {
		name: "None platform",
		infrastructureStatus: configv1.InfrastructureStatus{
			Platform: configv1.NonePlatformType,
			PlatformStatus: &configv1.PlatformStatus{
				Type: configv1.NonePlatformType,
			},
		},
		cloudProviderCount: 0,
	}, {
		name: "External platform, CloudControllerManager.State = External",
		infrastructureStatus: configv1.InfrastructureStatus{
			Platform: configv1.ExternalPlatformType,
			PlatformStatus: &configv1.PlatformStatus{
				Type: configv1.ExternalPlatformType,
				External: &configv1.ExternalPlatformStatus{
					CloudControllerManager: configv1.CloudControllerManagerStatus{
						State: configv1.CloudControllerManagerExternal,
					},
				},
			},
		},
		expected:           "external",
		cloudProviderCount: 0,
	}, {
		name: "External platform, CloudControllerManager.State = None",
		infrastructureStatus: configv1.InfrastructureStatus{
			Platform: configv1.ExternalPlatformType,
			PlatformStatus: &configv1.PlatformStatus{
				Type: configv1.ExternalPlatformType,
				External: &configv1.ExternalPlatformStatus{
					CloudControllerManager: configv1.CloudControllerManagerStatus{
						State: configv1.CloudControllerManagerNone,
					},
				},
			},
		},
		cloudProviderCount: 0,
	}, {
		name: "empty or unknown platform",
		infrastructureStatus: configv1.InfrastructureStatus{
			Platform: "",
			PlatformStatus: &configv1.PlatformStatus{
				Type: "",
			},
		},
		cloudProviderCount: 0,
	}, {
		name:                 "Not populated platform status",
		infrastructureStatus: configv1.InfrastructureStatus{},
		expected:             "",
		cloudProviderCount:   0,
		expectErrors:         false,
	}}
	for _, c := range cases {
		t.Run(string(c.name), func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			infra := &configv1.Infrastructure{
				ObjectMeta: v1.ObjectMeta{
					Name: "cluster",
				},
				Status: c.infrastructureStatus,
			}
			if err := indexer.Add(infra); err != nil {
				t.Fatal(err.Error())
			}

			listers := FakeInfrastructureLister{
				InfrastructureLister_: configlistersv1.NewInfrastructureLister(indexer),
				ResourceSync:          &FakeResourceSyncer{},
				ConfigMapLister_:      &FakeConfigMapLister{},
			}
			observerFunc := NewCloudProviderObserver("kube-controller-manager", c.skipCloudProviderExternal)
			result, errs := observerFunc(listers, events.NewInMemoryRecorder("cloud"), map[string]interface{}{})
			if errorsOccured := len(errs) > 0; c.expectErrors != errorsOccured {
				t.Fatalf("expected errors: %v, got: %v", c.expectErrors, errs)
			}
			cloudProvider, _, err := unstructured.NestedSlice(result, "extendedArguments", "cloud-provider")
			if err != nil {
				t.Fatal(err)
			}
			if c.skipCloudProviderExternal && len(cloudProvider) == 0 {
				return
			}
			if e, a := c.cloudProviderCount, len(cloudProvider); e != a {
				t.Fatalf("expected len(cloudProvider) == %d, got %d", e, a)
			}
			if c.cloudProviderCount > 0 {
				if e, a := c.expected, cloudProvider[0]; e != a {
					t.Errorf("expected cloud-provider=%s, got %s", e, a)
				}
			}
		})
	}
}
