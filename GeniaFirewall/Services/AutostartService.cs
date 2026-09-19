using System.Diagnostics;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using System.Runtime.InteropServices;

using GeniaFirewall.Models;

namespace GeniaFirewall.Services;

public sealed class AutostartService
{
    private const string LegacyRunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string LegacyValueName = "GeniaFirewall";
    private const string TaskName = "GeniaFirewall Portable Autostart";
    private const string TaskNamespace = "http://schemas.microsoft.com/windows/2004/02/mit/task";

    public bool IsEnabled()
    {
        if (TryGetScheduledTaskInfo(out var taskInfo) && taskInfo.Enabled)
            return true;

        // Treat the old 0.3 Run entry as enabled so MainWindow can migrate it automatically.
        return HasLegacyRunEntry();
    }

    public bool IsConfiguredForCurrentExecutable()
    {
        if (!TryGetScheduledTaskInfo(out var taskInfo) || !taskInfo.Enabled)
            return false;

        try
        {
            var expected = BuildExpectedTaskAction();
            return PathsEqual(taskInfo.Command, expected.Command) &&
                   string.Equals(taskInfo.Arguments, expected.Arguments, StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }

    public void SetEnabled(bool enabled)
    {
        if (enabled)
        {
            CreateOrReplaceScheduledTask();
            RemoveLegacyRunEntry();
        }
        else
        {
            DeleteScheduledTask();
            RemoveLegacyRunEntry();
        }
    }

    public string GetConfiguredCommand()
    {
        if (TryGetScheduledTaskInfo(out var taskInfo))
            return $"Task Scheduler: {taskInfo.Command} {taskInfo.Arguments}".Trim();

        using var key = Registry.CurrentUser.OpenSubKey(LegacyRunKeyPath, writable: false);
        return key?.GetValue(LegacyValueName) as string ?? string.Empty;
    }

    public string GetStatusDescription()
    {
        if (TryGetScheduledTaskInfo(out var taskInfo))
        {
            if (!taskInfo.Enabled)
                return LocalizationService.EffectiveLanguage == UiLanguage.Russian ? "Задача автозагрузки найдена, но отключена в Планировщике заданий." : "The autostart task exists but is disabled in Task Scheduler.";

            var russian = LocalizationService.EffectiveLanguage == UiLanguage.Russian;
            return IsConfiguredForCurrentExecutable()
                ? (russian ? "Работает · Планировщик заданий · текущий portable EXE и SHA-256 совпадают." : "Working · Task Scheduler · current portable EXE and SHA-256 match.")
                : (russian ? "Требует обновления · путь или SHA-256 portable EXE изменился. Нажмите «Сохранить»." : "Update required · portable EXE path or SHA-256 changed. Click Save.");
        }

        if (HasLegacyRunEntry())
            return LocalizationService.EffectiveLanguage == UiLanguage.Russian ? "Найдена устаревшая запись HKCU Run. Включите автозагрузку и нажмите «Сохранить» для миграции." : "A legacy HKCU Run entry was found. Enable autostart and click Save to migrate it.";

        return LocalizationService.EffectiveLanguage == UiLanguage.Russian ? "Отключена · задача автозагрузки не настроена." : "Disabled · autostart task is not configured.";
    }

    private static void CreateOrReplaceScheduledTask()
    {
        var executable = GetCurrentExecutablePath();
        var userSid = WindowsIdentity.GetCurrent().User?.Value;
        if (string.IsNullOrWhiteSpace(userSid))
            throw new InvalidOperationException("Не удалось определить SID текущего пользователя Windows.");

        var action = BuildExpectedTaskAction();
        var taskXml = BuildTaskXml(userSid, action.Command, action.Arguments, executable);
        var tempFile = Path.Combine(Path.GetTempPath(), $"GeniaFirewall-autostart-{Guid.NewGuid():N}.xml");

        try
        {
            // Task Scheduler accepts UTF-16 XML reliably on localized Windows builds.
            File.WriteAllText(tempFile, taskXml, Encoding.Unicode);

            var result = RunSchtasks("/Create", "/TN", TaskName, "/XML", tempFile, "/F");
            if (result.ExitCode != 0)
            {
                throw new InvalidOperationException(
                    "Не удалось создать задачу автозагрузки GeniaFirewall. " +
                    FormatToolError(result));
            }
        }
        finally
        {
            try
            {
                if (File.Exists(tempFile))
                    File.Delete(tempFile);
            }
            catch
            {
            }
        }
    }

    private static void DeleteScheduledTask()
    {
        var result = RunSchtasks("/Delete", "/TN", TaskName, "/F");
        // A missing task is harmless here. Re-query through the Task Scheduler COM API before failing.
        if (result.ExitCode != 0 && TryGetScheduledTaskInfo(out _))
        {
            throw new InvalidOperationException(
                "Не удалось удалить задачу автозагрузки GeniaFirewall. " +
                FormatToolError(result));
        }
    }

    private static bool TryGetScheduledTaskInfo(out ScheduledTaskInfo taskInfo)
    {
        taskInfo = default;
        object? serviceObject = null;
        object? folderObject = null;
        object? taskObject = null;
        object? definitionObject = null;
        object? actionsObject = null;
        object? actionObject = null;

        try
        {
            var serviceType = Type.GetTypeFromProgID("Schedule.Service", throwOnError: false);
            if (serviceType is null)
                return false;

            serviceObject = Activator.CreateInstance(serviceType);
            if (serviceObject is null)
                return false;

            dynamic service = serviceObject;
            service.Connect();
            folderObject = service.GetFolder("\\");
            dynamic folder = folderObject;
            taskObject = folder.GetTask(TaskName);
            dynamic task = taskObject;

            var enabled = (bool)task.Enabled;
            definitionObject = task.Definition;
            dynamic definition = definitionObject;
            actionsObject = definition.Actions;
            dynamic actions = actionsObject;
            if ((int)actions.Count < 1)
            {
                taskInfo = new ScheduledTaskInfo(enabled, string.Empty, string.Empty);
                return true;
            }

            actionObject = actions.Item(1);
            dynamic action = actionObject;
            var command = (string?)action.Path ?? string.Empty;
            var arguments = (string?)action.Arguments ?? string.Empty;
            taskInfo = new ScheduledTaskInfo(enabled, command, arguments);
            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            ReleaseComObject(actionObject);
            ReleaseComObject(actionsObject);
            ReleaseComObject(definitionObject);
            ReleaseComObject(taskObject);
            ReleaseComObject(folderObject);
            ReleaseComObject(serviceObject);
        }
    }

    private static (string Command, string Arguments) BuildExpectedTaskAction()
    {
        var executable = GetCurrentExecutablePath();
        using var executableStream = new FileStream(executable, FileMode.Open, FileAccess.Read, FileShare.Read);
        var expectedHash = Convert.ToHexString(SHA256.HashData(executableStream));
        var powerShell = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32",
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe");

        if (!File.Exists(powerShell))
            throw new FileNotFoundException("Не найден системный Windows PowerShell.", powerShell);

        var escapedPath = executable.Replace("'", "''", StringComparison.Ordinal);
        var script =
            "$ErrorActionPreference='Stop';" +
            $"$p='{escapedPath}';" +
            $"$h='{expectedHash}';" +
            "if(-not (Test-Path -LiteralPath $p -PathType Leaf)){exit 20};" +
            "$a=(Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash;" +
            "if($a -ne $h){exit 21};" +
            "Start-Process -FilePath $p -ArgumentList '--background'";

        var encodedCommand = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        var arguments = $"-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand {encodedCommand}";
        return (powerShell, arguments);
    }

    private static string BuildTaskXml(string userSid, string command, string arguments, string executable)
    {
        static string Escape(string value) => SecurityElement.Escape(value) ?? string.Empty;

        var now = DateTime.Now.ToString("yyyy-MM-dd'T'HH:mm:ss");
        var workingDirectory = Path.GetDirectoryName(executable) ?? AppContext.BaseDirectory;
        var xml = new StringBuilder(2048);

        xml.AppendLine("<?xml version=\"1.0\" encoding=\"UTF-16\"?>");
        xml.AppendLine($"<Task version=\"1.4\" xmlns=\"{TaskNamespace}\">");
        xml.AppendLine("  <RegistrationInfo>");
        xml.AppendLine($"    <Date>{Escape(now)}</Date>");
        xml.AppendLine("    <Author>GeniaFirewall</Author>");
        xml.AppendLine("    <Description>Starts GeniaFirewall Portable in the tray after logon. The action verifies the configured executable SHA-256 before elevation.</Description>");
        xml.AppendLine("  </RegistrationInfo>");
        xml.AppendLine("  <Triggers>");
        xml.AppendLine("    <LogonTrigger>");
        xml.AppendLine("      <Enabled>true</Enabled>");
        xml.AppendLine($"      <UserId>{Escape(userSid)}</UserId>");
        xml.AppendLine("      <Delay>PT10S</Delay>");
        xml.AppendLine("    </LogonTrigger>");
        xml.AppendLine("  </Triggers>");
        xml.AppendLine("  <Principals>");
        xml.AppendLine("    <Principal id=\"Author\">");
        xml.AppendLine($"      <UserId>{Escape(userSid)}</UserId>");
        xml.AppendLine("      <LogonType>InteractiveToken</LogonType>");
        xml.AppendLine("      <RunLevel>HighestAvailable</RunLevel>");
        xml.AppendLine("    </Principal>");
        xml.AppendLine("  </Principals>");
        xml.AppendLine("  <Settings>");
        xml.AppendLine("    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>");
        xml.AppendLine("    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>");
        xml.AppendLine("    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>");
        xml.AppendLine("    <AllowHardTerminate>true</AllowHardTerminate>");
        xml.AppendLine("    <StartWhenAvailable>true</StartWhenAvailable>");
        xml.AppendLine("    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>");
        xml.AppendLine("    <IdleSettings>");
        xml.AppendLine("      <StopOnIdleEnd>false</StopOnIdleEnd>");
        xml.AppendLine("      <RestartOnIdle>false</RestartOnIdle>");
        xml.AppendLine("    </IdleSettings>");
        xml.AppendLine("    <AllowStartOnDemand>true</AllowStartOnDemand>");
        xml.AppendLine("    <Enabled>true</Enabled>");
        xml.AppendLine("    <Hidden>false</Hidden>");
        xml.AppendLine("    <RunOnlyIfIdle>false</RunOnlyIfIdle>");
        xml.AppendLine("    <WakeToRun>false</WakeToRun>");
        xml.AppendLine("    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>");
        xml.AppendLine("    <Priority>7</Priority>");
        xml.AppendLine("  </Settings>");
        xml.AppendLine("  <Actions Context=\"Author\">");
        xml.AppendLine("    <Exec>");
        xml.AppendLine($"      <Command>{Escape(command)}</Command>");
        xml.AppendLine($"      <Arguments>{Escape(arguments)}</Arguments>");
        xml.AppendLine($"      <WorkingDirectory>{Escape(workingDirectory)}</WorkingDirectory>");
        xml.AppendLine("    </Exec>");
        xml.AppendLine("  </Actions>");
        xml.AppendLine("</Task>");

        return xml.ToString();
    }

    private static string GetCurrentExecutablePath()
    {
        var executable = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executable) || !Path.IsPathFullyQualified(executable) || !File.Exists(executable))
            throw new InvalidOperationException("Не удалось определить путь к GeniaFirewall.exe.");

        return Path.GetFullPath(executable);
    }

    private static bool PathsEqual(string first, string second)
    {
        try
        {
            return string.Equals(Path.GetFullPath(first), Path.GetFullPath(second), StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return string.Equals(first, second, StringComparison.OrdinalIgnoreCase);
        }
    }

    private static bool HasLegacyRunEntry()
    {
        using var key = Registry.CurrentUser.OpenSubKey(LegacyRunKeyPath, writable: false);
        return !string.IsNullOrWhiteSpace(key?.GetValue(LegacyValueName) as string);
    }

    private static void RemoveLegacyRunEntry()
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(LegacyRunKeyPath, writable: true);
            key?.DeleteValue(LegacyValueName, throwOnMissingValue: false);
        }
        catch
        {
            // A stale legacy Run entry is non-fatal. The scheduled task remains authoritative.
        }
    }

    private static ToolResult RunSchtasks(params string[] arguments)
    {
        var schtasks = Path.Combine(Environment.SystemDirectory, "schtasks.exe");
        var startInfo = new ProcessStartInfo
        {
            FileName = schtasks,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);

        using var process = Process.Start(startInfo)
                            ?? throw new InvalidOperationException("Не удалось запустить schtasks.exe.");
        var standardOutput = process.StandardOutput.ReadToEnd();
        var standardError = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return new ToolResult(process.ExitCode, standardOutput, standardError);
    }

    private static string FormatToolError(ToolResult result)
    {
        var text = string.Join(" ", new[] { result.StandardError, result.StandardOutput }
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim()));
        return string.IsNullOrWhiteSpace(text) ? $"schtasks.exe завершился с кодом {result.ExitCode}." : text;
    }

    private static void ReleaseComObject(object? value)
    {
        try
        {
            if (value is not null && Marshal.IsComObject(value))
                Marshal.FinalReleaseComObject(value);
        }
        catch
        {
        }
    }

    private readonly record struct ScheduledTaskInfo(bool Enabled, string Command, string Arguments);
    private readonly record struct ToolResult(int ExitCode, string StandardOutput, string StandardError);
}
