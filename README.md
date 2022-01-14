[comment]: # "Auto-generated SOAR connector documentation"
# CloudPassage Halo

Publisher: Splunk  
Connector Version: 2\.0\.4  
Product Vendor: CloudPassage  
Product Name: CloudPassage Halo  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.9\.39220  

This app supports a variety of investigative actions on CloudPassage Halo

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a CloudPassage Halo asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | URL \(eg\: https\://api\.cloudpassage\.com\)
**client\_id** |  required  | string | Client ID
**client\_secret** |  required  | password | Client secret

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate credentials provided for connectivity  
[get system info](#action-get-system-info) - Get information about a server  
[list packages](#action-list-packages) - List all packages on a given server  
[get package](#action-get-package) - Get information about a package  
[list processes](#action-list-processes) - List all processes on a given server  
[get process](#action-get-process) - Get information about a process  
[list vulnerabilities](#action-list-vulnerabilities) - List all vulnerabilities on a given server  
[get vulnerability](#action-get-vulnerability) - Get information about a vulnerability  
[list users](#action-list-users) - List all users on a given server  
[get user](#action-get-user) - Get information about a user  
[list servers](#action-list-servers) - List all servers for a given user, process, package and vulnerability  

## action: 'test connectivity'
Validate credentials provided for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get system info'
Get information about a server

Type: **investigate**  
Read only: **True**

At least one parameter out of <b>aws\_instance\_id</b>, <b>ip</b> and <b>hostname</b> is mandatory\. When we get multiple servers with same hostname, we will consider first matching server if in case user only provides the hostname in input parameters\(aws\_instance\_id/ip/hostname\)\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**aws\_instance\_id** |  optional  | AWS instance ID | string |  `cloudpassagehalo aws instance id` 
**ip** |  optional  | IP | string |  `ip` 
**hostname** |  optional  | Hostname | string |  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.created\_at | string | 
action\_result\.data\.\*\.group\_path | string | 
action\_result\.data\.\*\.interfaces\.\*\.mac\_address | string | 
action\_result\.data\.\*\.docker\_labels | string | 
action\_result\.data\.\*\.docker\_running | boolean | 
action\_result\.data\.\*\.docker\_version | string | 
action\_result\.data\.\*\.docker\_installed | boolean | 
action\_result\.data\.\*\.docker\_inspection | string | 
action\_result\.data\.\*\.docker\_parameters | string | 
action\_result\.data\.\*\.containerd\_running | boolean | 
action\_result\.data\.\*\.containerd\_version | string | 
action\_result\.data\.\*\.container\_inspection | string | 
action\_result\.data\.\*\.containerd\_installed | boolean | 
action\_result\.data\.\*\.containerd\_parameters | string | 
action\_result\.data\.\*\.agent\_distribution\_type | string | 
action\_result\.data\.\*\.read\_only | boolean | 
action\_result\.data\.\*\.self\_verification\_failed | boolean | 
action\_result\.data\.\*\.kernel\_machine | string | 
action\_result\.data\.\*\.state | string | 
action\_result\.data\.\*\.url | string |  `url` 
action\_result\.data\.\*\.interfaces\.\*\.netmask | string | 
action\_result\.data\.\*\.interfaces\.\*\.ip\_address | string |  `ip` 
action\_result\.data\.\*\.interfaces\.\*\.name | string | 
action\_result\.data\.\*\.interfaces\.\*\.display\_name | string | 
action\_result\.data\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.last\_state\_change | string | 
action\_result\.data\.\*\.primary\_ip\_address | string |  `ip` 
action\_result\.data\.\*\.connecting\_ip\_fqdn | string | 
action\_result\.data\.\*\.daemon\_version | string | 
action\_result\.data\.\*\.platform\_version | string | 
action\_result\.data\.\*\.reported\_fqdn | string | 
action\_result\.data\.\*\.server\_label | string | 
action\_result\.data\.\*\.os\_version | string | 
action\_result\.data\.\*\.platform | string | 
action\_result\.data\.\*\.connecting\_ip\_address | string |  `ip` 
action\_result\.data\.\*\.kernel\_name | string | 
action\_result\.data\.\*\.group\_id | string | 
action\_result\.data\.\*\.group\_name | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.firewall\_policy | string | 
action\_result\.data\.\*\.firewall\_policy\.status | string | 
action\_result\.data\.\*\.firewall\_policy\.name | string | 
action\_result\.data\.\*\.firewall\_policy\.url | string |  `url` 
action\_result\.data\.\*\.firewall\_policy\.installed | string | 
action\_result\.data\.\*\.firewall\_policy\.last\_checked | string | 
action\_result\.data\.\*\.firewall\_policy\.id | string | 
action\_result\.data\.\*\.aws\_ec2\.ec2\_account\_id | string | 
action\_result\.data\.\*\.aws\_ec2\.ec2\_security\_groups | string | 
action\_result\.data\.\*\.aws\_ec2\.ec2\_availability\_zone | string | 
action\_result\.data\.\*\.aws\_ec2\.ec2\_instance\_type | string | 
action\_result\.data\.\*\.aws\_ec2\.ec2\_instance\_id | string |  `cloudpassagehalo aws instance id` 
action\_result\.data\.\*\.aws\_ec2\.ec2\_private\_ip | string |  `ip` 
action\_result\.data\.\*\.aws\_ec2\.ec2\_kernel\_id | string | 
action\_result\.data\.\*\.aws\_ec2\.ec2\_image\_id | string | 
action\_result\.data\.\*\.aws\_ec2\.ec2\_region | string | 
action\_result\.data\.\*\.proxy | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.aws\_instance\_id | string |  `cloudpassagehalo aws instance id` 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.hostname | string |  `host name` 
action\_result\.summary\.reported\_fqdn | string | 
action\_result\.summary\.primary\_ip\_address | string | 
action\_result\.summary\.hostname | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list packages'
List all packages on a given server

Type: **investigate**  
Read only: **True**

At least one parameter out of <b>aws\_instance\_id</b>, <b>ip</b> and <b>hostname</b> is mandatory\. When we get multiple servers with same hostname, we will consider first matching server if in case user only provides the hostname in input parameters\(aws\_instance\_id/ip/hostname\)\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**aws\_instance\_id** |  optional  | AWS instance ID | string |  `cloudpassagehalo aws instance id` 
**ip** |  optional  | IP | string |  `ip` 
**hostname** |  optional  | Hostname | string |  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.max\_cvss | numeric | 
action\_result\.data\.\*\.cve\_entries\.\*\.cvss\_version | numeric | 
action\_result\.data\.\*\.cve\_entries\.\*\.remotely\_exploitable | boolean | 
action\_result\.data\.\*\.remotely\_exploitable | boolean | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.vendor | string | 
action\_result\.data\.\*\.package\_name | string |  `cloudpassagehalo package name` 
action\_result\.data\.\*\.url | string |  `url` 
action\_result\.data\.\*\.package\_version | string | 
action\_result\.data\.\*\.cpe | string | 
action\_result\.data\.\*\.critical | boolean | 
action\_result\.data\.\*\.cve\_entries\.\*\.cve\_entry | string |  `cloudpassagehalo cve number` 
action\_result\.data\.\*\.cve\_entries\.\*\.cvss\_score | numeric | 
action\_result\.data\.\*\.cve\_entries\.\*\.suppressed | boolean | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.install\_date | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.aws\_instance\_id | string |  `cloudpassagehalo aws instance id` 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.hostname | string |  `host name` 
action\_result\.summary\.total\_packages | numeric | 
action\_result\.summary\.reported\_fqdn | string | 
action\_result\.summary\.primary\_ip\_address | string | 
action\_result\.summary\.hostname | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get package'
Get information about a package

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**package\_name** |  required  | Package name | string |  `cloudpassagehalo package name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.max\_cvss | numeric | 
action\_result\.data\.\*\.cve\_entries\.\*\.cvss\_version | numeric | 
action\_result\.data\.\*\.cve\_entries\.\*\.remotely\_exploitable | boolean | 
action\_result\.data\.\*\.remotely\_exploitable | boolean | 
action\_result\.data\.\*\.server\_info\_primary\_ip\_address | string |  `ip` 
action\_result\.data\.\*\.server\_info\_hostname | string |  `host name` 
action\_result\.data\.\*\.server\_info\_id | string | 
action\_result\.data\.\*\.server\_info\_ec2\_instance\_id | string |  `cloudpassagehalo aws instance id` 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.cpe | string | 
action\_result\.data\.\*\.url | string |  `url` 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.vendor | string | 
action\_result\.data\.\*\.critical | boolean | 
action\_result\.data\.\*\.install\_date | string | 
action\_result\.data\.\*\.package\_name | string |  `cloudpassagehalo package name` 
action\_result\.data\.\*\.package\_version | string | 
action\_result\.data\.\*\.cve\_entries\.\*\.cve\_entry | string |  `cloudpassagehalo cve number` 
action\_result\.data\.\*\.cve\_entries\.\*\.cvss\_score | numeric | 
action\_result\.data\.\*\.cve\_entries\.\*\.suppressed | boolean | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.package\_name | string |  `cloudpassagehalo package name` 
action\_result\.summary\.total\_packages | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list processes'
List all processes on a given server

Type: **investigate**  
Read only: **True**

At least one parameter out of <b>aws\_instance\_id</b>, <b>ip</b> and <b>hostname</b> is mandatory\. When we get multiple servers with same hostname, we will consider first matching server if in case user only provides the hostname in input parameters\(aws\_instance\_id/ip/hostname\)\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**aws\_instance\_id** |  optional  | AWS instance ID | string |  `cloudpassagehalo aws instance id` 
**ip** |  optional  | IP | string |  `ip` 
**hostname** |  optional  | Hostname | string |  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.pid | string |  `pid` 
action\_result\.data\.\*\.ppid | string |  `pid` 
action\_result\.data\.\*\.user | string | 
action\_result\.data\.\*\.state | string | 
action\_result\.data\.\*\.command | string | 
action\_result\.data\.\*\.cpu\_percent | string | 
action\_result\.data\.\*\.cpu\_usage | string | 
action\_result\.data\.\*\.memory\_usage | string | 
action\_result\.data\.\*\.process\_name | string |  `process name` 
action\_result\.data\.\*\.memory\_percent | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.aws\_instance\_id | string |  `cloudpassagehalo aws instance id` 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.hostname | string |  `host name` 
action\_result\.summary\.total\_processes | numeric | 
action\_result\.summary\.reported\_fqdn | string | 
action\_result\.summary\.primary\_ip\_address | string | 
action\_result\.summary\.hostname | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get process'
Get information about a process

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**process\_name** |  required  | Process name | string |  `process name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.server\_info\_primary\_ip\_address | string |  `ip` 
action\_result\.data\.\*\.server\_info\_hostname | string |  `host name` 
action\_result\.data\.\*\.server\_info\_id | string | 
action\_result\.data\.\*\.server\_info\_ec2\_instance\_id | string |  `cloudpassagehalo aws instance id` 
action\_result\.data\.\*\.pid | string |  `pid` 
action\_result\.data\.\*\.ppid | string |  `pid` 
action\_result\.data\.\*\.user | string | 
action\_result\.data\.\*\.state | string | 
action\_result\.data\.\*\.command | string | 
action\_result\.data\.\*\.cpu\_percent | string | 
action\_result\.data\.\*\.cpu\_usage | string | 
action\_result\.data\.\*\.memory\_usage | string | 
action\_result\.data\.\*\.process\_name | string |  `process name` 
action\_result\.data\.\*\.memory\_percent | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.process\_name | string |  `process name` 
action\_result\.summary\.total\_processes | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list vulnerabilities'
List all vulnerabilities on a given server

Type: **investigate**  
Read only: **True**

At least one parameter out of <b>aws\_instance\_id</b>, <b>ip</b> and <b>hostname</b> is mandatory\. When we get multiple servers with same hostname, we will consider first matching server if in case user only provides the hostname in input parameters\(aws\_instance\_id/ip/hostname\)\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**aws\_instance\_id** |  optional  | AWS instance ID | string |  `cloudpassagehalo aws instance id` 
**ip** |  optional  | IP | string |  `ip` 
**hostname** |  optional  | Hostname | string |  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.scan\.findings\.\*\.max\_cvss | numeric | 
action\_result\.data\.\*\.scan\.findings\.\*\.cve\_entries\.\*\.cvss\_version | numeric | 
action\_result\.data\.\*\.scan\.findings\.\*\.cve\_entries\.\*\.remotely\_exploitable | boolean | 
action\_result\.data\.\*\.scan\.findings\.\*\.remotely\_exploitable | boolean | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.connecting\_ip\_address | string |  `ip` 
action\_result\.data\.\*\.state | string | 
action\_result\.data\.\*\.scan\.id | string | 
action\_result\.data\.\*\.scan\.url | string |  `url` 
action\_result\.data\.\*\.scan\.module | string | 
action\_result\.data\.\*\.scan\.status | string | 
action\_result\.data\.\*\.scan\.created\_at | string | 
action\_result\.data\.\*\.scan\.completed\_at | string | 
action\_result\.data\.\*\.scan\.analysis\_started\_at | string | 
action\_result\.data\.\*\.scan\.analysis\_completed\_at | string | 
action\_result\.data\.\*\.scan\.agent\_started\_at | string | 
action\_result\.data\.\*\.scan\.agent\_completed\_at | string | 
action\_result\.data\.\*\.scan\.server\_id | string | 
action\_result\.data\.\*\.scan\.server\_hostname | string |  `host name` 
action\_result\.data\.\*\.scan\.server\_url | string |  `url` 
action\_result\.data\.\*\.scan\.critical\_findings\_count | numeric | 
action\_result\.data\.\*\.scan\.non\_critical\_findings\_count | numeric | 
action\_result\.data\.\*\.scan\.ok\_findings\_count | numeric | 
action\_result\.data\.\*\.scan\.findings\.\*\.id | string | 
action\_result\.data\.\*\.scan\.findings\.\*\.url | string |  `url` 
action\_result\.data\.\*\.scan\.findings\.\*\.package\_name | string |  `cloudpassagehalo package name` 
action\_result\.data\.\*\.scan\.findings\.\*\.package\_version | string | 
action\_result\.data\.\*\.scan\.findings\.\*\.critical | boolean | 
action\_result\.data\.\*\.scan\.findings\.\*\.status | string | 
action\_result\.data\.\*\.scan\.findings\.\*\.cve\_entries\.\*\.cve\_entry | string |  `cloudpassagehalo cve number` 
action\_result\.data\.\*\.scan\.findings\.\*\.cve\_entries\.\*\.cvss\_score | numeric | 
action\_result\.data\.\*\.scan\.findings\.\*\.cve\_entries\.\*\.suppressed | boolean | 
action\_result\.data\.\*\.scan\.findings\.\*\.cpe | string | 
action\_result\.data\.\*\.scan\.findings\.\*\.vendor | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.aws\_instance\_id | string |  `cloudpassagehalo aws instance id` 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.hostname | string |  `host name` 
action\_result\.summary\.critical\_packages\_count | numeric | 
action\_result\.summary\.non\_critical\_packages\_count | numeric | 
action\_result\.summary\.ok\_packages\_count | numeric | 
action\_result\.summary\.reported\_fqdn | string | 
action\_result\.summary\.primary\_ip\_address | string | 
action\_result\.summary\.hostname | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get vulnerability'
Get information about a vulnerability

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**cve\_number** |  required  | Common Vulnerability and Exposure number | string |  `cloudpassagehalo cve number` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.scan\.findings\.\*\.max\_cvss | numeric | 
action\_result\.data\.\*\.scan\.findings\.\*\.cve\_entries\.\*\.cvss\_version | numeric | 
action\_result\.data\.\*\.scan\.findings\.\*\.cve\_entries\.\*\.remotely\_exploitable | boolean | 
action\_result\.data\.\*\.scan\.findings\.\*\.remotely\_exploitable | boolean | 
action\_result\.data\.\*\.server\_info\_primary\_ip\_address | string |  `ip` 
action\_result\.data\.\*\.server\_info\_hostname | string |  `host name` 
action\_result\.data\.\*\.server\_info\_id | string | 
action\_result\.data\.\*\.server\_info\_ec2\_instance\_id | string |  `cloudpassagehalo aws instance id` 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.connecting\_ip\_address | string |  `ip` 
action\_result\.data\.\*\.state | string | 
action\_result\.data\.\*\.scan\.id | string | 
action\_result\.data\.\*\.scan\.url | string |  `url` 
action\_result\.data\.\*\.scan\.module | string | 
action\_result\.data\.\*\.scan\.status | string | 
action\_result\.data\.\*\.scan\.findings\.\*\.id | string | 
action\_result\.data\.\*\.scan\.findings\.\*\.cpe | string | 
action\_result\.data\.\*\.scan\.findings\.\*\.url | string |  `url` 
action\_result\.data\.\*\.scan\.findings\.\*\.status | string | 
action\_result\.data\.\*\.scan\.findings\.\*\.vendor | string | 
action\_result\.data\.\*\.scan\.findings\.\*\.critical | boolean | 
action\_result\.data\.\*\.scan\.findings\.\*\.cve\_entries\.\*\.cve\_entry | string |  `cloudpassagehalo cve number` 
action\_result\.data\.\*\.scan\.findings\.\*\.cve\_entries\.\*\.cvss\_score | numeric | 
action\_result\.data\.\*\.scan\.findings\.\*\.cve\_entries\.\*\.suppressed | boolean | 
action\_result\.data\.\*\.scan\.findings\.\*\.package\_name | string |  `cloudpassagehalo package name` 
action\_result\.data\.\*\.scan\.findings\.\*\.package\_version | string | 
action\_result\.data\.\*\.scan\.findings\.\*\.install\_date | string | 
action\_result\.data\.\*\.scan\.server\_id | string | 
action\_result\.data\.\*\.scan\.created\_at | string | 
action\_result\.data\.\*\.scan\.server\_url | string |  `url` 
action\_result\.data\.\*\.scan\.completed\_at | string | 
action\_result\.data\.\*\.scan\.server\_hostname | string |  `host name` 
action\_result\.data\.\*\.scan\.agent\_started\_at | string | 
action\_result\.data\.\*\.scan\.ok\_findings\_count | numeric | 
action\_result\.data\.\*\.scan\.agent\_completed\_at | string | 
action\_result\.data\.\*\.scan\.analysis\_started\_at | string | 
action\_result\.data\.\*\.scan\.analysis\_completed\_at | string | 
action\_result\.data\.\*\.scan\.critical\_findings\_count | numeric | 
action\_result\.data\.\*\.scan\.non\_critical\_findings\_count | numeric | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.cve\_number | string |  `cloudpassagehalo cve number` 
action\_result\.summary\.total\_servers | numeric | 
action\_result\.summary\.total\_critical\_findings\_count | numeric | 
action\_result\.summary\.total\_non\_critical\_findings\_count | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list users'
List all users on a given server

Type: **investigate**  
Read only: **True**

At least one parameter out of <b>aws\_instance\_id</b>, <b>ip</b> and <b>hostname</b> is mandatory\. When we get multiple servers with same hostname, we will consider first matching server if in case user only provides the hostname in input parameters\(aws\_instance\_id/ip/hostname\)\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**aws\_instance\_id** |  optional  | AWS instance ID | string |  `cloudpassagehalo aws instance id` 
**ip** |  optional  | IP | string |  `ip` 
**hostname** |  optional  | Hostname | string |  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.groups | string | 
action\_result\.data\.\*\.expires | string | 
action\_result\.data\.\*\.home\_exists | boolean | 
action\_result\.data\.\*\.sudo\_access | string | 
action\_result\.data\.\*\.last\_login\_from | string | 
action\_result\.data\.\*\.password\_locked | boolean | 
action\_result\.data\.\*\.password\_expired | boolean | 
action\_result\.data\.\*\.password\_expires | string | 
action\_result\.data\.\*\.last\_password\_change | string | 
action\_result\.data\.\*\.password\_locked\_with | string | 
action\_result\.data\.\*\.disabled\_after\_days\_inactive | numeric | 
action\_result\.data\.\*\.days\_warn\_before\_password\_expiration | numeric | 
action\_result\.data\.\*\.maximum\_days\_between\_password\_changes | numeric | 
action\_result\.data\.\*\.minimum\_days\_between\_password\_changes | numeric | 
action\_result\.data\.\*\.gid | string | 
action\_result\.data\.\*\.uid | string | 
action\_result\.data\.\*\.sid | string | 
action\_result\.data\.\*\.url | string |  `url` 
action\_result\.data\.\*\.home | string | 
action\_result\.data\.\*\.admin | boolean | 
action\_result\.data\.\*\.shell | string | 
action\_result\.data\.\*\.active | boolean | 
action\_result\.data\.\*\.comment | string | 
action\_result\.data\.\*\.locked | boolean | 
action\_result\.data\.\*\.os\_type | string | 
action\_result\.data\.\*\.group\_id | string | 
action\_result\.data\.\*\.username | string |  `user name` 
action\_result\.data\.\*\.server\_id | string | 
action\_result\.data\.\*\.server\_name | string |  `host name` 
action\_result\.data\.\*\.server\_label | string | 
action\_result\.data\.\*\.last\_login\_at | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.aws\_instance\_id | string |  `cloudpassagehalo aws instance id` 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.parameter\.hostname | string |  `host name` 
action\_result\.summary\.total\_users | numeric | 
action\_result\.summary\.reported\_fqdn | string | 
action\_result\.summary\.primary\_ip\_address | string | 
action\_result\.summary\.hostname | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get user'
Get information about a user

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**username** |  required  | Username | string |  `user name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.account\.password\_locked | boolean | 
action\_result\.data\.\*\.account\.password\_locked\_with | string | 
action\_result\.data\.\*\.full\_name | string | 
action\_result\.data\.\*\.server\_info\_primary\_ip\_address | string |  `ip` 
action\_result\.data\.\*\.server\_info\_hostname | string |  `host name` 
action\_result\.data\.\*\.server\_info\_id | string | 
action\_result\.data\.\*\.server\_info\_ec2\_instance\_id | string |  `cloudpassagehalo aws instance id` 
action\_result\.data\.\*\.account\.gid | string | 
action\_result\.data\.\*\.account\.uid | string | 
action\_result\.data\.\*\.account\.sid | string | 
action\_result\.data\.\*\.account\.url | string |  `url` 
action\_result\.data\.\*\.account\.home | string | 
action\_result\.data\.\*\.account\.admin | boolean | 
action\_result\.data\.\*\.account\.shell | string | 
action\_result\.data\.\*\.account\.active | boolean | 
action\_result\.data\.\*\.account\.groups | string | 
action\_result\.data\.\*\.account\.comment | string | 
action\_result\.data\.\*\.account\.locked | boolean | 
action\_result\.data\.\*\.account\.ssh\_acl | string | 
action\_result\.data\.\*\.account\.username | string |  `user name` 
action\_result\.data\.\*\.account\.full\_name | string | 
action\_result\.data\.\*\.account\.home\_exists | boolean | 
action\_result\.data\.\*\.account\.password\_required | boolean | 
action\_result\.data\.\*\.account\.password\_changeable | boolean | 
action\_result\.data\.\*\.account\.sudo\_access | string | 
action\_result\.data\.\*\.account\.sudo\_access\.\*\.as\_user\.\* | string | 
action\_result\.data\.\*\.account\.last\_login\_at | string | 
action\_result\.data\.\*\.account\.last\_login\_from | string | 
action\_result\.data\.\*\.account\.days\_since\_disabled | numeric | 
action\_result\.data\.\*\.account\.last\_password\_change | string | 
action\_result\.data\.\*\.account\.expires | string | 
action\_result\.data\.\*\.account\.disabled\_after\_days\_inactive | numeric | 
action\_result\.data\.\*\.account\.days\_warn\_before\_password\_expiration | numeric | 
action\_result\.data\.\*\.account\.maximum\_days\_between\_password\_changes | numeric | 
action\_result\.data\.\*\.account\.minimum\_days\_between\_password\_changes | numeric | 
action\_result\.data\.\*\.account\.password\_expires | string | 
action\_result\.data\.\*\.account\.password\_expired | boolean | 
action\_result\.data\.\*\.account\.ssh\_authorized\_keys | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.username | string |  `user name` 
action\_result\.summary\.total\_users | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list servers'
List all servers for a given user, process, package and vulnerability

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**username** |  optional  | Username | string |  `user name` 
**process\_name** |  optional  | Process name | string |  `process name` 
**package\_name** |  optional  | Package name | string |  `cloudpassagehalo package name` 
**cve\_number** |  optional  | Common Vulnerability and Exposure number | string |  `cloudpassagehalo cve number` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.created\_at | string | 
action\_result\.data\.\*\.group\_path | string | 
action\_result\.data\.\*\.interfaces\.\*\.mac\_address | string | 
action\_result\.data\.\*\.docker\_labels | string | 
action\_result\.data\.\*\.docker\_running | boolean | 
action\_result\.data\.\*\.docker\_version | string | 
action\_result\.data\.\*\.docker\_installed | boolean | 
action\_result\.data\.\*\.docker\_inspection | string | 
action\_result\.data\.\*\.docker\_parameters | string | 
action\_result\.data\.\*\.containerd\_running | boolean | 
action\_result\.data\.\*\.containerd\_version | string | 
action\_result\.data\.\*\.container\_inspection | string | 
action\_result\.data\.\*\.containerd\_installed | boolean | 
action\_result\.data\.\*\.containerd\_parameters | string | 
action\_result\.data\.\*\.agent\_distribution\_type | string | 
action\_result\.data\.\*\.read\_only | boolean | 
action\_result\.data\.\*\.self\_verification\_failed | boolean | 
action\_result\.data\.\*\.kernel\_machine | string | 
action\_result\.data\.\*\.state | string | 
action\_result\.data\.\*\.url | string |  `url` 
action\_result\.data\.\*\.interfaces\.\*\.netmask | string | 
action\_result\.data\.\*\.interfaces\.\*\.ip\_address | string |  `ip` 
action\_result\.data\.\*\.interfaces\.\*\.name | string | 
action\_result\.data\.\*\.interfaces\.\*\.display\_name | string | 
action\_result\.data\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.last\_state\_change | string | 
action\_result\.data\.\*\.primary\_ip\_address | string |  `ip` 
action\_result\.data\.\*\.connecting\_ip\_fqdn | string | 
action\_result\.data\.\*\.daemon\_version | string | 
action\_result\.data\.\*\.platform\_version | string | 
action\_result\.data\.\*\.reported\_fqdn | string | 
action\_result\.data\.\*\.server\_label | string | 
action\_result\.data\.\*\.os\_version | string | 
action\_result\.data\.\*\.platform | string | 
action\_result\.data\.\*\.connecting\_ip\_address | string |  `ip` 
action\_result\.data\.\*\.kernel\_name | string | 
action\_result\.data\.\*\.group\_id | string | 
action\_result\.data\.\*\.group\_name | string | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.firewall\_policy | string | 
action\_result\.data\.\*\.firewall\_policy\.status | string | 
action\_result\.data\.\*\.firewall\_policy\.name | string | 
action\_result\.data\.\*\.firewall\_policy\.url | string |  `url` 
action\_result\.data\.\*\.firewall\_policy\.installed | string | 
action\_result\.data\.\*\.firewall\_policy\.last\_checked | string | 
action\_result\.data\.\*\.firewall\_policy\.id | string | 
action\_result\.data\.\*\.aws\_ec2\.ec2\_account\_id | string | 
action\_result\.data\.\*\.aws\_ec2\.ec2\_security\_groups | string | 
action\_result\.data\.\*\.aws\_ec2\.ec2\_availability\_zone | string | 
action\_result\.data\.\*\.aws\_ec2\.ec2\_instance\_type | string | 
action\_result\.data\.\*\.aws\_ec2\.ec2\_instance\_id | string |  `cloudpassagehalo aws instance id` 
action\_result\.data\.\*\.aws\_ec2\.ec2\_private\_ip | string |  `ip` 
action\_result\.data\.\*\.aws\_ec2\.ec2\_kernel\_id | string | 
action\_result\.data\.\*\.aws\_ec2\.ec2\_image\_id | string | 
action\_result\.data\.\*\.aws\_ec2\.ec2\_region | string | 
action\_result\.data\.\*\.proxy | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.username | string |  `user name` 
action\_result\.parameter\.process\_name | string |  `process name` 
action\_result\.parameter\.package\_name | string |  `cloudpassagehalo package name` 
action\_result\.parameter\.cve\_number | string |  `cloudpassagehalo cve number` 
action\_result\.summary\.total\_servers | numeric | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 