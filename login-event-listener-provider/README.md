# login-event-listener-provider

# login-event-listener-provider

## description

This event listener provider performs two functions:

1. it listens for the **LOGIN** event:
   - updates `last-login` attribute
   - emits a log entry at `WARN` level
2. it periodically (nightly, by default) disables users who have
   expired passwords or inactive accounts beyond the grace period
   specified in the 'Disable Users' password policy

## usage

1. copy the JAR to the deployment directory
2. optionally modify `standalone.xml`

   ```xml
   <subsystem xmlns="urn:jboss:domain:keycloak-server:1.1">
       <spi name="eventsListener">
           <provider name="login-event-listener" enabled="true">
               <properties>
                   <!-- in seconds -->
                   <property name="taskInterval" value="30"/>
               </properties>
           </provider>
       </spi>
   </subsystem>
   ```
3. add a `last-login` attribute to the realm's declarative user profile with
   - permissions
     - user can view set false
     - admin can view set true
     - user can edit set false
     - admin can edit set false
   - validations
     - pattern validator
       - pattern:`^[0-9]+$`
       - message: `invalid timestamp (in milliseconds)`
4. add `login-event-listener` to the realm's event listeners

---

© 2024 Luca Filipozzi. Some rights reserved. See [LICENSE][license].

[license]: https://github.com/LucaFilipozzi/keycloak-extensions/blob/main/LICENSE.md

