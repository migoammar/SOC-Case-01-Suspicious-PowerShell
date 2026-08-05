# PowerShell Credential Harvesting Investigation

## Objective

Investigate suspicious PowerShell activity using Splunk to identify and
analyze potentially malicious behavior.

------------------------------------------------------------------------

## Environment

-   Windows VM
-   Splunk
-   EVTX-ATTACK log file

------------------------------------------------------------------------

## Timeline

1.  Opened Splunk and monitored security events.

2.  Identified suspicious PowerShell activity.

3.  Filtered logs using:

    ``` spl
    index=* EventCode=4104
    ```

4.  Reviewed the PowerShell Script Block.

5.  Observed an execution policy bypass command.

6.  Continued reviewing the PowerShell script.

7.  Identified a script requesting user credentials.

8.  Continued the investigation based on the observed behavior.

------------------------------------------------------------------------

## Findings

-   Suspicious PowerShell activity was identified.
-   Event ID 4104 was used to analyze the Script Block.
-   Execution Policy Bypass was observed.
-   The script requested user credentials.
-   The script read and validated the entered credentials.
-   The behavior was classified as **Credential Harvesting Behavior**.
-   No conclusive evidence of credential exfiltration was identified
    during this investigation.

------------------------------------------------------------------------

## Evidence

### Search Query

``` spl
index=* EventCode=4104
```

### Evidence 1

-   Event ID: **4104**
-   PowerShell Script Block Logging.

### Evidence 2

Command observed:

``` powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```

### Evidence 3

The script displayed a credential prompt using:

``` powershell
$Host.UI.PromptForCredential(...)
```

### Evidence 4

The script accessed the entered password using:

``` powershell
.GetNetworkCredential().Password
```

### Evidence 5

The script validated the supplied credentials before continuing.

------------------------------------------------------------------------

## Conclusion

The investigation identified suspicious PowerShell behavior consistent
with credential harvesting. However, based on the available evidence, no
confirmed proof of credential exfiltration or successful compromise was
observed. Further correlation with additional telemetry (such as Event
ID 4688 and network activity) would be required.
