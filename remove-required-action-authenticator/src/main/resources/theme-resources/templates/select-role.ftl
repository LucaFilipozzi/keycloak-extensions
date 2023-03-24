<!-- Copyright 2023 Luca Filipozzi. Some rights reserved. See LICENSE. -->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
  <#if section = "title">
    select role
  <#elseif section = "header">
    select role
  <#elseif section = "form">
    <form action="${url.loginAction}" class="${properties.kcFormClass!}" id="select-role-form" method="post">
      <div class="${properties.kcFormGroupClass!}">
        <div class="${properties.kcInputWrapperClass!}">
          <#list availableRoles>
            <fieldset>
              <#items as availableRole>
                <div><!-- TODO apply classes -->
                  <input type="radio" name="selectedRole" id="selectedRole-${availableRole_index}" value="${availableRole}" required="true"/>
                  <label for="selectedRole-${availableRole_index}">${availableRole}</label>
                </div>
              </#items>
            </fieldset>
          </#list>
        </div>
        <div class="${properties.kcInputWrapperClass}">
          <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}" type="submit" value="${msg("doSubmit")}"/>
        </div>
      </div>
    </form>
  </#if>
</@layout.registrationLayout>
