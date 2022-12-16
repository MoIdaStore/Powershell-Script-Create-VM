##Create New VM
$VName = "AD01"
New-VM -Name $VName -Path "C:\VM" -SwitchName "Lan" -MemoryStartupBytes 2048MB -Generation 2
Set-VMProcessor -VMName $VName -Count 2
Set-VM -Name $VName -AutomaticCheckpointsEnabled $false
New-VHD -Path "C:\VM\$($VName)\$($VName).vhdx" -Differencing -ParentPath 'C:\VM\Windows2019Template.vhdx'
Add-VMHardDiskDrive -VMName $($VName) -Path "C:\VM\$($VName)\$($VName).vhdx"

#How to set boot order to HardDisk
Get-VMFirmware "AD01"
$win10g2 = Get-VMFirmware "AD01"
$win10g2.bootorder

$hddrive = $win10g2.BootOrder[1]
$networkdrive = $win10g2.BootOrder[0]

Set-VMFirmware -VMName AD01 -BootOrder $hddrive,$networkdrive

##Konfigurerar Nätverkskort
Invoke-Command -VMName "AD01" -Credential (Get-Credential) {


     ###Konfigurerar IP Address
    New-NetIPAddress -IPAddress "192.168.10.5" -PrefixLength 24 -DefaultGateway "192.168.10.1" -InterfaceAlias "Ethernet"
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "192.168.10.5"
  
    


    Get-LocalUser | Where-Object {$_.name -Like "Admin*"} | Set-LocalUser -Password (ConvertTo-SecureString -String "Sommar2020" -AsPlainText -Force)

    Rename-Computer -NewName "AD01" -Restart




}


###Konfigurera AD Server
Invoke-Command -VMName "AD01" -Credential (Get-Credential) {


    ###Installera Active Directory###
    Install-WindowsFeature -Name "AD-Domain-Services" -IncludeManagementTools

    ###Promote AD###
    Install-ADDSForest -domainname "Mstile.se"




    }
###Skapa OU
Invoke-Command -VMName "AD01" -Credential (Get-Credential) -ScriptBlock{


        ##Create a new OU
        New-ADOrganizationalUnit -Name Mstile






}


###Skapa Nya användare

$Users = Import-Csv C:\VM\user.csv -Encoding UTF8

Invoke-Command -VMName "AD01" -Credential (Get-Credential) -ScriptBlock{

    Foreach($user in $using:users){


         New-ADUser -Path "OU=Mstile,DC=Mstile,DC=SE" -GivenName $user.givenname -Surname $user.surname -Name "$($user.givenname) $($user.surname)" -SamAccountName $user.samaccountname -AccountPassword (ConvertTo-SecureString -String "Sommar2020" -AsPlainText -Force)




    }

    Get-ADUser -Filter * -SearchBase "OU=Mstile,DC=Mstile,DC=SE"



    }




#Change OU users UPN suffix till specific OU

Invoke-Command -VMName "AD01" -Credential (get-credential) -ScriptBlock{

Get-ADUser -Filter * -SearchBase "OU=GBG,OU=Mstile,DC=Mstile,DC=se" -Properties userPrincipalName | foreach { Set-ADUser $_ -UserPrincipalName (“{0}@{1}” -f $_.name,”mstile.com”)}

}



#Change User Logon name to Firstname.Lastname@domain.com

Invoke-Command -VMName "AD01" -Credential (get-credential) -ScriptBlock{

Get-ADUser -Filter "UserPrincipalName -like '* *'" -SearchBase "OU=GBG,OU=Mstile,DC=Mstile,DC=se" | ForEach {

    Set-ADUser -Identity $_.SamAccountName -UserPrincipalName "$($_.GivenName).$($_.Surname)@mstile.se" }

}