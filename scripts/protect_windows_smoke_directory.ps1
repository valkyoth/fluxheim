[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$Directory)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Test fixtures only: establish inheritance before creating config or secrets.
$item = Get-Item -LiteralPath $Directory -Force
if (-not $item.PSIsContainer -or
    ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
    @(Get-ChildItem -LiteralPath $Directory -Force).Count -ne 0) {
    throw 'smoke fixture must be an empty, non-reparse directory'
}
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$acl = [Security.AccessControl.DirectorySecurity]::new()
# Only the DACL is changed; touching audit rules would require SeSecurityPrivilege.
$acl.SetSecurityDescriptorSddlForm(
    "D:P(A;OICI;FA;;;$sid)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
    [Security.AccessControl.AccessControlSections]::Access)
# Windows PowerShell's Set-Acl also attempts to persist the audit section.
$item.SetAccessControl($acl)

$actual = Get-Acl -LiteralPath $Directory
$rules = @($actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
$allowed = @($sid, 'S-1-5-18', 'S-1-5-32-544')
if (-not $actual.AreAccessRulesProtected -or $rules.Count -ne 3) {
    throw 'smoke directory did not retain its protected ACL'
}
foreach ($rule in $rules) {
    if ($rule.IdentityReference.Value -notin $allowed -or $rule.IsInherited -or
        $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
        $rule.InheritanceFlags -ne ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit) -or
        $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
        throw 'smoke directory ACL or child inheritance differs from the private fixture policy'
    }
}
