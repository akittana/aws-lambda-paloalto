# aws-lambda-paloalto

Python code for AWS Lambda that monitors changes in AWS and adds/removes rules automatically from a Palo Alto gateway instance running in AWS.
More details on features and design: https://securitynik.blogspot.ca/2016/07/aws-security-automating-palo-alto.html

Current events monitored:
  * StartInstances: Event indicating that a new instance was started
  * AuthorizeSecurityGroupIngress: Event indicating that a new rule was adding to an existing security group
  * StopInstances: An instance was stopped.
  * RevokeSecurityGroupIngress: A rule was removed from a security group.

Before running, the following variables have to be set in the lambda.lambda_handler function:
  * pa_ip: IP address of your Palo Alto gateway.
  * pa_key: Access key for the Palo Alto gateway (Refer to the Pan-OS XML API User guide for more details on this, and specifically this page).
  * pa_bottom_rule: Name of the rule which the lambda function would be adding on top of. This would usually be the clean up rule in your security policy.
  * pa_zone_untrust: Name of the outside zone configured on the Palo Alto gateway.
  * pa_zone_trust: Name of the inside zone configured on the Palo Alto gateway.
  * pa_sgp: name of security profile group in Palo Alto to be set on rules added.
  * igwId: Instance id of the Palo Alto gateway.
  
Code Features/Design
 * Adding rules
  The lambda function will monitor the following two events for adding new rules:
    * StartInstances: Event indicating that a new instance was started
    * AuthorizeSecurityGroupIngress: Event indicating that a new rule was adding to an existing security group
  Once any of these two events is detected, the function will extract the relevant information for rules required to the instances affected, and add the corresponding rules.
  Rules added have the name corresponding to the type of event that triggered them. If the rule added is because of an instance started, then it’s named ‘instanceId-#’ where # is increased with every rule added, but if it is due to a change in a security group, then the naming is ‘groupid-#’. The naming convention is used by the code to track the rules it added.
 * Unnecessary rules
  Since the Palo Alto gateway is running as an internet gateway, there are many scenarios that are not relevant, and the code will try to filter out these events so that we don’t make any unnecessary changes to the Palo Alto gateway. The following scenarios would not introduce changes to the Palo Alto gateway:
   * Instances that are started but that don’t use the Palo Alto as their internet gateway. For example, there can be multiple internet gateways configured and we're only concerns with instances that use the Palo Alto to reach the internet.
   * In instances with multiple interfaces, the code checks all the interfaces, and only includes those that use the Palo Alto instance as an internet gateway.
   * Security group rules that have a source from within the AWS VPC will be filtered out. The Palo Alto gateway in this instance is used as an internet gateway, and so traffic from within the VPC would not pass through it.
   * Security group rules that reference other security groups as a source will also not be included. These rules imply that the traffic would be local to the VPC and so would not pass the internet gateway.
 
 Also before adding a rule, a test is made to make sure traffic is not already allowed, and only after making sure that traffic is denied, we will add a new rule.
 
 * Rule location
 The code will also only add rules at the bottom, so that the security administrator can create rules at the top of the rule base that would override anything added dynamically. This can be used to control the rules automatically added. Furthermore, we specify in the code the bottom most rule that the new rules have to go above, and we can use this to control the location of the rules so that certain rules always remain at the bottom (For example, our clean up rule).

 * Cleaning up
 When instances are stopped or rules in security groups are removed, we want any rules that we added to be removed. To avoid removing any permanent rules added by the security administrator, the code will only remove rules that it added previously to the rule base (This is can be controlled using the naming). The following events are monitored as triggers:
   * StopInstances: An instance was stopped.
   * RevokeSecurityGroupIngress: A rule was removed from a security group.
