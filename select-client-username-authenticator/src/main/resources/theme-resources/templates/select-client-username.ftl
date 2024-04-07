<!-- © 2024 Luca Filipozzi. Some rights reserved. See LICENSE. -->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
    <#if section = "title">
      select client username
    <#elseif section = "header">
      select client username
    <#elseif section = "form">
      <form action="${url.loginAction}" class="${properties.kcFormClass!}"
            id="select-client-username-form" method="post">
        <div class="${properties.kcFormGroupClass!}">
          <div class="${properties.kcInputWrapperClass!}">
              <#list availableClientUsernames>
                <fieldset>
                    <#items as availableClientUsername>
                      <div>
                        <input type="radio" name="selectedClientUsername"
                               id="selectedClientUsername-${availableClientUsername_index}"
                               value="${availableClientUsername}" required="true"/>
                        <label
                            for="selectedClientUsername-${availableClientUsername_index}">${availableClientUsername}</label>
                      </div>
                    </#items>
                </fieldset>
              </#list>
          </div>
          <div class="${properties.kcInputWrapperClass}">
            <input
                class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}"
                type="submit" value="${msg("doSubmit")}"/>
          </div>
        </div>
      </form>
    </#if>
</@layout.registrationLayout>
