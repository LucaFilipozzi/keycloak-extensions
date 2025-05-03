# login-event-listener-provider

# login-event-listener-provider

## description

This event listener provider performs three functions:

1. it listens for the **LOGIN** event:
   - updates `last-login` attribute
   - emits a log entry at `WARN` level
2. it periodically (per `taskInterval` configuration parameter) disables
   users who have expired passwords or inactive accounts beyond the grace
   period specified in the 'Disable Users' password policy
3. it periodically (per `taskInterval` configuration parameter) determines
   (per `warningIntervals` configuration parameter) whether an email warning
   should be sent to users who have passwords that will be within the warning
   interval, updating the `last-warning` and `days-to-password-expiry` attributes

## usage

1. copy the JAR to the deployment directory
2. optionally modify `standalone.xml`

   ```xml
   <subsystem xmlns="urn:jboss:domain:keycloak-server:1.1">
       <spi name="eventsListener">
           <provider name="login-event-listener" enabled="true">
               <properties>
                   <!-- positive ISO8601 duration: P1D PT30S-->
                   <property name="taskInterval" value="PT30S"/>
                   <!-- negative ISO8601 durations, comma separated: -P28D, -P14D, -P7D, -P1D -->
                   <property name="warningIntervals" value="-P28D, -P14D, -P7D, -P1D"/>
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
4. add a `last-warning` attribute to the realm's declarative user profile with
    - permissions
        - user can view set false
        - admin can view set true
        - user can edit set false
        - admin can edit set false
    - validations
        - pattern validator
            - pattern:`^[0-9]+$`
            - message: `invalid timestamp (in milliseconds)`
5. add a `days-to-password-recovery` attribute to the realm's declarative user profile with
    - permissions
        - user can view set false
        - admin can view set true
        - user can edit set false
        - admin can edit set false
    - validations
        - integer validator
            - min: 0
6. add `login-event-listener` to the realm's event listeners
7. to the theme add
    - `$KEYCLOAK_HOME/themes/<theme>/email/messages/messages_en.properties` containing
       ```
      passwordExpiringSubject=Your password is expiring soon!
      passwordExpiringBody=Your password in realm {0} is expiring in {1} day(s). Please log in and update your password before it expires.
      passwordExpiringBodyHtml=<p>Your password in realm {0} is expiring in {1} day(s). Please log in and update your password before it expires.</p>
      ```
   - `$KEYCLOAK_HOME/themes/<theme>/email/html/password-expiring.ftl` containing
      ```
     <html>
     <body>
     ${kcSanitize(msg("passwordExpiringBodyHtml", realm.displayName, passwordExpiringDays))?no_esc}
     </body>
     </html>
     ```
   - `$KEYCLOAK_HOME/themes/<mytheme>/email/text/password-expiring.ftl` containing
      ```
      <#ftl output_format="plainText">
      ${msg("passwordExpiringBody", realm.displayName, passwordExpiringDays)}
      ```
8. set the realm's email theme to `mytheme`

---

© 2025 Luca Filipozzi. Some rights reserved. See [LICENSE][license].

[license]: https://github.com/LucaFilipozzi/keycloak-extensions/blob/main/LICENSE.md

