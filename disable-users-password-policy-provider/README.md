# disable-users-password-policy-provider

## description

This password policy provider schedules a daily task that disables users who have:
expired passwords or inactive accounts beyond a configurable grace period.

The default grace period is 60 days.

## usage

1. copy the JAR to the deployment directory
2. optionally modify `standalone.xml` to change the task interval
   ```xml
   <subsystem xmlns="urn:jboss:domain:keycloak-server:1.1">
       <spi name="password-policy">
           <provider name="disable-users-password-policy" enabled="true">
               <properties>
                   <!-- in milliseconds -->
                   <property name="taskInterval" value="30000"/>
               </properties>
           </provider>
       </spi>
   </subsystem>
   ```
3. add the __Disable Users__ password policy

Please note that this provider requires that users' `last-login` attribute be
populated with a timestamp (in milliseconds). The login event listener provider
provides this functionality.

---

© 2024 Luca Filipozzi. Some rights reserved. See [LICENSE][license].

[license]: https://github.com/LucaFilipozzi/keycloak-extensions/blob/main/LICENSE.md
