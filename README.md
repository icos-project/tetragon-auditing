# Tetragon Auditing
Tetragon is an advanced observability tool designed for monitoring, troubleshooting, and securing cloud-native applications and infrastructure. It leverages eBPF (extended Berkeley Packet Filter) technology to provide deep insights into system behavior, enabling real-time detection and resolution of issues without impacting performance.

## Installation
```sh
cd tetragon-auditing
helm install  icos-tetragon tetragon-chart/tetragon ## default namespace 
```

## Pre-defined policies
Upon installation, Tetragon in the scope of ICOS project has some pre-defined policies located at 
tetragon-auditing/tetragon-chart/tetragon/standard-policies-yaml:
- sudo-invocations
- kernel-module loading
- priviledges raise ( from upriviledged processes)
- user namespace creation ( from upriviledged processes)

## Application defined policies
Tetragon is able to monitor an application real-time by creating specific policies.
Currently the available policies are the following:
- external http calls from within the application
- file-system monitoring

## Testing the policies
Tetragon exposes the occurencies of the triggered policies to a prometheus endpoint
exposed as a sevice listening at port 2112. This enpdoint can be invoked by:
```sh
curl {ENDPOINT-CLUSTER-IP}:2112/metrics
```
To filter out the triggered policies:
```sh
curl {ENDPOINT-CLUSTER-IP}:2112/metrics | grep tetragon_policy_events_total
```
### Pre-defined policies
On the host if we execute the following commands one by one:
```sh
sudo pwd (or any other command using sudo) -> triggers sudo-invocation policy 
setuid 1 ls (or any other command using setuid) -> triggers priviledges-raise
unshare --user --map-root-user /bin/bash -> triggers priviledges-raise
insmod a-kernel-module (load a kernel module) -> triggers monitor-kernel-modules
```
An example output from prometheus enpoind would be:
```sh
tetragon_policy_events_total{binary="/usr/bin/setuid",hook="kprobe:__sys_setuid",namespace="",pod="",policy="privileges-raise",workload=""} 1
tetragon_policy_events_total{binary="/usr/bin/sudo",hook="kprobe:__x64_sys_execve",namespace="",pod="",policy="sudo-invocations",workload=""} 1
tetragon_policy_events_total{binary="/usr/bin/unshare",hook="kprobe:create_user_ns",namespace="",pod="",policy="privileges-raise",workload=""} 1
```
### Appilcation Policies
One importat thing to mention here is that the monitoring of a specific application or a specific pod of an application is achieved via labeling.
A label "key:value" must be present under the label section:

```sh
apiVersion: v1
kind: Pod
metadata:
  name: example-pod
  namespace: Anampsace
  labels:
    key: value
```
The created policies for the application need to specify also this label to keep track of the application:
```sh
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "example-policy"
spec:
  podSelector:
    matchLabels:
      key: "value" # the value must be in double quotes
```
#### Testing Application Policies
To test policies that track a specific application (or a set of pods) we need a sample application.
A sample is provided at the root folder of the repository (the test app runs under test namespace):
```sh
cd tetragon-auditing
kubectl apply -f test-app.yaml
kubectl get pods -n test #Check the running pods of the application
```
In this sample application many pods have the following label under metadata section:
```sh
labels:
    org: empire
```
The defined policies will use this label to track the application:
```sh
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "a-test-policy"
spec:
  podSelector:
    matchLabels:
      org: "empire"
```
Apply the policies that track the sample app:
```sh
cd application-defined-policies
kubectl apply -f application-file-system.yaml
kubectl apply -f external-requests.yaml
```
To simulate an unpriviledged access to the pod and trigger the policies:
```sh
kubectl exec -it tiefighter -n test -- /bin/bash
touch /etc/some_file.txt # create a file in /etc folder
cat /etc/shadow # access a file in /etc folder
curl www.google.com # make an external call 
```
An example output from prometheus enpoind would be:
```sh
tetragon_policy_events_total{binary="/usr/bin/touch",hook="kprobe:security_file_permission",namespace="test",pod="tiefighter",policy="application-file-system-access",workload="tiefighter"} 1
tetragon_policy_events_total{binary="/usr/bin/curl",hook="kprobe:tcp_connect",namespace="test",pod="tiefighter",policy="external-http-call",workload="tiefighter"} 1
tetragon_policy_events_total{binary="/usr/bin/cat",hook="kprobe:security_file_permission",namespace="test",pod="tiefighter",policy="application-file-system-access",workload="tiefighter"} 1
```
# Legal
The Tetragon Auditing is released under the Apache license.
Copyright © 2022-2024  ICOS Consortium. All rights reserved.

🇪🇺 This work has received funding from the European Union's HORIZON research and innovation programme under grant agreement No. 101070177.
