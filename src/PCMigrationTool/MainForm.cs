using System.Diagnostics;
using System.Drawing;
using PCMigrationTool.Core.Infrastructure;
using PCMigrationTool.Core.Models;
using PCMigrationTool.Core.Services;

namespace PCMigrationTool;

internal sealed class MainForm : Form
{
    private static readonly Color Navy = Color.FromArgb(24, 44, 73);
    private static readonly Color Blue = Color.FromArgb(38, 112, 214);
    private static readonly Color Page = Color.FromArgb(246, 248, 251);

    private readonly AppServices services;
    private readonly ScreenCaptureService screenCapture;
    private readonly TextBox activityLog = new();
    private readonly ToolStripStatusLabel statusLabel = new("Ready");
    private readonly ToolStripProgressBar progress = new() { Style = ProgressBarStyle.Marquee, Visible = false };
    private readonly TabControl tabs = new();
    private readonly CancellationTokenSource lifetime = new();

    private readonly TextBox gatherDestination = new();
    private readonly CheckBox includeOneDrive = new() { Text = "Include locally available OneDrive content", AutoSize = true };
    private readonly CheckBox skipProfile = new() { Text = "Skip user-profile copy", AutoSize = true };
    private readonly CheckBox allowMissingBrowsers = new() { Text = "Continue when browser password exports are missing", AutoSize = true };
    private readonly Label browserStatus = new() { AutoSize = true };
    private readonly Button gatherButton = PrimaryButton("Start gather");
    private readonly Button browserButton = SecondaryButton("Prepare browser exports");

    private readonly TextBox manifestPath = new();
    private readonly TextBox profileSource = new();
    private readonly TextBox requestedHostname = new();
    private readonly RadioButton localAccount = new() { Text = "Local account", Checked = true, AutoSize = true };
    private readonly RadioButton domainAccount = new() { Text = "Join domain", AutoSize = true };
    private readonly TextBox localUsername = new();
    private readonly TextBox localPassword = new() { UseSystemPasswordChar = true };
    private readonly CheckBox localAdministrator = new() { Text = "Make local administrator", AutoSize = true };
    private readonly TextBox domainName = new();
    private readonly TextBox domainOu = new();
    private readonly TextBox domainJoinAccount = new();
    private readonly TextBox domainJoinPassword = new() { UseSystemPasswordChar = true };
    private readonly TextBox domainTargetUser = new();
    private readonly Button restoreButton = PrimaryButton("Prepare restore");
    private readonly List<Control> domainControls = [];
    private readonly List<Control> localControls = [];

    public MainForm(AppServices services, ScreenCaptureService screenCapture)
    {
        this.services = services;
        this.screenCapture = screenCapture;
        Text = $"PC Migration Tool {Program.Version}";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(980, 720);
        Size = new Size(1180, 840);
        BackColor = Page;
        AutoScaleMode = AutoScaleMode.Dpi;

        Controls.Add(BuildMainContent());
        Controls.Add(BuildHeader());
        services.Logger.EntryWritten += OnLogEntry;
        FormClosed += (_, _) =>
        {
            services.Logger.EntryWritten -= OnLogEntry;
            lifetime.Cancel();
            lifetime.Dispose();
        };
        Shown += (_, _) => RefreshBrowserStatus();
    }

    private Control BuildHeader()
    {
        Panel header = new() { Dock = DockStyle.Top, Height = 82, BackColor = Navy, Padding = new Padding(24, 13, 24, 10) };
        Label title = new()
        {
            Text = "PC Migration Tool",
            ForeColor = Color.White,
            Font = new Font("Segoe UI Semibold", 22),
            AutoSize = true,
            Location = new Point(22, 10)
        };
        Label subtitle = new()
        {
            Text = "Gather, transfer, and restore Windows user environments",
            ForeColor = Color.FromArgb(194, 209, 230),
            Font = new Font("Segoe UI", 9.5f),
            AutoSize = true,
            Location = new Point(25, 51)
        };
        Label identity = new()
        {
            Text = $"{Environment.MachineName}  •  {Environment.UserDomainName}\\{Environment.UserName}  •  Administrator: {(ElevationHost.IsAdministrator() ? "Yes" : "No")}",
            ForeColor = Color.White,
            Font = new Font("Segoe UI", 9.5f),
            AutoSize = true,
            Anchor = AnchorStyles.Top | AnchorStyles.Right,
            Location = new Point(680, 28)
        };
        header.Resize += (_, _) => identity.Left = Math.Max(430, header.ClientSize.Width - identity.Width - 24);
        header.Controls.AddRange([title, subtitle, identity]);
        return header;
    }

    private Control BuildMainContent()
    {
        TableLayoutPanel layout = new()
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(18, 15, 18, 10),
            RowCount = 3,
            ColumnCount = 1
        };
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 72));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 28));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));

        tabs.Dock = DockStyle.Fill;
        tabs.Font = new Font("Segoe UI", 10);
        tabs.TabPages.Add(BuildGatherPage());
        tabs.TabPages.Add(BuildRestorePage());

        GroupBox activity = new() { Text = "Activity", Dock = DockStyle.Fill, Padding = new Padding(10) };
        activityLog.Dock = DockStyle.Fill;
        activityLog.Multiline = true;
        activityLog.ReadOnly = true;
        activityLog.ScrollBars = ScrollBars.Vertical;
        activityLog.BackColor = Color.FromArgb(19, 26, 36);
        activityLog.ForeColor = Color.FromArgb(220, 231, 244);
        activityLog.Font = new Font("Cascadia Mono", 9);
        activity.Controls.Add(activityLog);

        StatusStrip status = new() { Dock = DockStyle.Fill, SizingGrip = false };
        status.Items.Add(statusLabel);
        status.Items.Add(new ToolStripStatusLabel { Spring = true });
        status.Items.Add(progress);

        layout.Controls.Add(tabs, 0, 0);
        layout.Controls.Add(activity, 0, 1);
        layout.Controls.Add(status, 0, 2);
        return layout;
    }

    private TabPage BuildGatherPage()
    {
        TabPage page = NewPage("Gather from this PC");
        Panel scroll = new() { Dock = DockStyle.Fill, AutoScroll = true };
        TableLayoutPanel form = NewFormLayout(8);
        AddHeading(form, 0, "Create a complete migration repository");
        AddPathField(form, 1, "Destination base path", gatherDestination, BrowseForFolder);
        AddFullRow(form, 2, includeOneDrive);
        AddFullRow(form, 3, skipProfile);
        AddFullRow(form, 4, allowMissingBrowsers);

        FlowLayoutPanel browserRow = new() { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.LeftToRight };
        browserRow.Controls.Add(browserButton);
        browserRow.Controls.Add(browserStatus);
        browserButton.Click += (_, _) => PrepareBrowserExports();
        AddLabeledControl(form, 5, "Browser passwords", browserRow);

        Label note = new()
        {
            Text = "Output is always stored under <destination>\\<HOST>_<DATE>\\PC_SWAP_INFO. Network settings are recorded but never applied blindly to a different adapter.",
            AutoSize = true,
            MaximumSize = new Size(850, 0),
            ForeColor = Color.FromArgb(75, 85, 99)
        };
        AddFullRow(form, 6, note);
        gatherButton.AutoSize = true;
        gatherButton.Click += async (_, _) => await RunGatherAsync();
        AddFullRow(form, 7, gatherButton);
        scroll.Controls.Add(form);
        page.Controls.Add(scroll);
        return page;
    }

    private TabPage BuildRestorePage()
    {
        TabPage page = NewPage("Restore to this PC");
        Panel scroll = new() { Dock = DockStyle.Fill, AutoScroll = true };
        TableLayoutPanel form = NewFormLayout(15);
        AddHeading(form, 0, "Prepare the destination and resilient resume workflow");
        AddPathField(form, 1, "Manifest", manifestPath, BrowseForManifest);
        AddPathField(form, 2, "Profile source", profileSource, BrowseForFolder);
        AddLabeledControl(form, 3, "New hostname (optional)", requestedHostname);

        FlowLayoutPanel mode = new() { Dock = DockStyle.Fill, AutoSize = true };
        mode.Controls.AddRange([localAccount, domainAccount]);
        AddLabeledControl(form, 4, "Account mode", mode);
        localAccount.CheckedChanged += (_, _) => UpdateAccountMode();
        domainAccount.CheckedChanged += (_, _) => UpdateAccountMode();

        AddModeField(form, 5, "Local username", localUsername, localControls);
        AddModeField(form, 6, "Local password", localPassword, localControls);
        AddFullRow(form, 7, localAdministrator);
        localControls.Add(localAdministrator);

        AddModeField(form, 8, "Domain name", domainName, domainControls);
        AddModeField(form, 9, "OU distinguished name (optional)", domainOu, domainControls);
        AddModeField(form, 10, "Domain join account", domainJoinAccount, domainControls);
        AddModeField(form, 11, "Domain join password", domainJoinPassword, domainControls);
        AddModeField(form, 12, "Target domain username", domainTargetUser, domainControls);

        Label safety = new()
        {
            Text = "The executable and state are cached under ProgramData before any reboot. Profile restoration runs only for the selected target user.",
            AutoSize = true,
            MaximumSize = new Size(850, 0),
            ForeColor = Color.FromArgb(75, 85, 99)
        };
        AddFullRow(form, 13, safety);
        FlowLayoutPanel actions = new() { Dock = DockStyle.Fill, AutoSize = true };
        restoreButton.Click += async (_, _) => await RunRestoreAsync();
        Button defaults = SecondaryButton("Open Default Apps");
        defaults.Click += (_, _) => Process.Start(new ProcessStartInfo("ms-settings:defaultapps") { UseShellExecute = true });
        actions.Controls.AddRange([restoreButton, defaults]);
        AddFullRow(form, 14, actions);

        manifestPath.TextChanged += (_, _) => InferProfileSource();
        scroll.Controls.Add(form);
        page.Controls.Add(scroll);
        UpdateAccountMode();
        return page;
    }

    private async Task RunGatherAsync()
    {
        string destination = gatherDestination.Text.Trim();
        if (!Directory.Exists(destination))
        {
            ShowWarning("Choose an existing destination folder.");
            return;
        }

        await RunOperationAsync("Gathering migration data", async cancellationToken =>
        {
            RepositoryPaths expected = RepositoryLayout.Create(destination, Environment.MachineName, DateTimeOffset.Now);
            RepositoryLayout.EnsureDirectories(expected);
            services.Logger.SetLogPath(expected.LogPath);
            screenCapture.CaptureAll(expected.ScreenshotsPath);
            GatherResult result = await services.Gather.RunAsync(
                new GatherOptions(
                    destination,
                    includeOneDrive.Checked,
                    skipProfile.Checked,
                    allowMissingBrowsers.Checked,
                    Program.Version),
                cancellationToken,
                line => services.Logger.Info("ROBOCOPY: " + line));
            RefreshBrowserStatus();
            Process.Start(new ProcessStartInfo(result.Paths.InfoRoot) { UseShellExecute = true });
            MessageBox.Show(
                $"Gather completed successfully.\n\nManifest: {result.Paths.ManifestPath}\nReport: {result.ReportPath}",
                "Gather complete",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        });
    }

    private async Task RunRestoreAsync()
    {
        if (!File.Exists(manifestPath.Text.Trim()))
        {
            ShowWarning("Choose a valid manifest.json file.");
            return;
        }
        if (localAccount.Checked && string.IsNullOrWhiteSpace(localUsername.Text))
        {
            ShowWarning("Enter the local target username.");
            return;
        }
        if (domainAccount.Checked && new[] { domainName.Text, domainJoinAccount.Text, domainJoinPassword.Text, domainTargetUser.Text }.Any(string.IsNullOrWhiteSpace))
        {
            ShowWarning("Domain name, join account, join password, and target username are required.");
            return;
        }

        await RunOperationAsync("Preparing restore", async cancellationToken =>
        {
            DomainJoinOptions? domain = domainAccount.Checked
                ? new DomainJoinOptions(
                    domainName.Text.Trim(),
                    EmptyToNull(domainOu.Text),
                    domainJoinAccount.Text.Trim(),
                    domainJoinPassword.Text,
                    domainTargetUser.Text.Trim())
                : null;
            RestorePreparation prepared = await services.Restore.PrepareAsync(
                new RestoreOptions(
                    manifestPath.Text.Trim(),
                    EmptyToNull(requestedHostname.Text),
                    EmptyToNull(profileSource.Text),
                    localAccount.Checked ? localUsername.Text.Trim() : null,
                    localAccount.Checked ? EmptyToNull(localPassword.Text) : null,
                    localAdministrator.Checked,
                    domain,
                    true),
                cancellationToken);

            localPassword.Clear();
            domainJoinPassword.Clear();
            if (prepared.RebootRequired)
            {
                DialogResult reboot = MessageBox.Show(
                    "Restore preparation is complete and Windows must reboot. Reboot now?",
                    "Reboot required",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question);
                if (reboot == DialogResult.Yes)
                {
                    Process.Start(new ProcessStartInfo("shutdown.exe", "/r /t 0") { UseShellExecute = false });
                }
            }
            else
            {
                await services.Resume.RunSystemAsync(prepared.CachedStatePath, cancellationToken);
                MessageBox.Show(
                    "System restore steps completed. Sign in as the target user to finish the profile restore.",
                    "Restore prepared",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
        });
    }

    private void PrepareBrowserExports()
    {
        string destination = gatherDestination.Text.Trim();
        if (!Directory.Exists(destination))
        {
            ShowWarning("Choose an existing destination folder first.");
            return;
        }
        RepositoryPaths paths = RepositoryLayout.Create(destination, Environment.MachineName, DateTimeOffset.Now);
        RepositoryLayout.EnsureDirectories(paths);
        services.Logger.SetLogPath(paths.LogPath);
        IReadOnlyList<BrowserInfo> browsers = services.Browser.DetectInstalled();
        services.Browser.OpenPasswordExportPages(browsers);
        Process.Start(new ProcessStartInfo(paths.BrowserExportsPath) { UseShellExecute = true });
        browserStatus.Text = $"Export {browsers.Count} browser file(s) into: {paths.BrowserExportsPath}";
        browserStatus.ForeColor = Color.DarkOrange;
    }

    private void RefreshBrowserStatus()
    {
        IReadOnlyList<BrowserInfo> browsers = services.Browser.DetectInstalled();
        browserStatus.Text = browsers.Count == 0
            ? "No supported browsers detected"
            : "Detected: " + string.Join(", ", browsers.Select(static browser => browser.DisplayName));
        browserStatus.ForeColor = browsers.Count == 0 ? Color.DimGray : Color.DarkBlue;
    }

    private void InferProfileSource()
    {
        if (!File.Exists(manifestPath.Text.Trim()))
        {
            return;
        }
        try
        {
            RepositoryPaths paths = RepositoryLayout.FromManifest(manifestPath.Text.Trim(), DateTimeOffset.Now);
            profileSource.Text = Directory.Exists(paths.ProfilePath) ? paths.ProfilePath : paths.HostRoot;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidDataException)
        {
            services.Logger.Warning(exception.Message);
        }
    }

    private async Task RunOperationAsync(string status, Func<CancellationToken, Task> operation)
    {
        SetBusy(true, status);
        try
        {
            await operation(lifetime.Token);
            statusLabel.Text = "Ready";
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            services.Logger.Error(status + " failed", exception);
            MessageBox.Show(exception.Message, "Operation failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            statusLabel.Text = "Failed";
        }
        finally
        {
            SetBusy(false, statusLabel.Text ?? string.Empty);
        }
    }

    private void SetBusy(bool busy, string status)
    {
        gatherButton.Enabled = !busy;
        restoreButton.Enabled = !busy;
        browserButton.Enabled = !busy;
        progress.Visible = busy;
        statusLabel.Text = status;
        UseWaitCursor = busy;
    }

    private void OnLogEntry(object? sender, LogEntry entry)
    {
        if (IsDisposed || !IsHandleCreated)
        {
            return;
        }
        BeginInvoke((Action)(() =>
        {
            activityLog.AppendText(entry + Environment.NewLine);
            activityLog.SelectionStart = activityLog.TextLength;
            activityLog.ScrollToCaret();
        }));
    }

    private void UpdateAccountMode()
    {
        foreach (Control control in localControls)
        {
            control.Enabled = localAccount.Checked;
        }
        foreach (Control control in domainControls)
        {
            control.Enabled = domainAccount.Checked;
        }
    }

    private void BrowseForFolder(TextBox target)
    {
        using FolderBrowserDialog dialog = new() { ShowNewFolderButton = true };
        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            target.Text = dialog.SelectedPath;
        }
    }

    private void BrowseForManifest(TextBox target)
    {
        using OpenFileDialog dialog = new()
        {
            Filter = "Migration manifest (manifest.json)|manifest.json|JSON files (*.json)|*.json",
            CheckFileExists = true,
            Title = "Select migration manifest"
        };
        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            target.Text = dialog.FileName;
        }
    }

    private static TabPage NewPage(string text) => new() { Text = text, BackColor = Page, Padding = new Padding(14) };

    private static TableLayoutPanel NewFormLayout(int rows)
    {
        TableLayoutPanel form = new()
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            ColumnCount = 2,
            RowCount = rows,
            Padding = new Padding(8)
        };
        form.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 245));
        form.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (int index = 0; index < rows; index++)
        {
            form.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        }
        return form;
    }

    private static void AddHeading(TableLayoutPanel form, int row, string text)
    {
        Label heading = new()
        {
            Text = text,
            Font = new Font("Segoe UI Semibold", 16),
            ForeColor = Navy,
            AutoSize = true,
            Margin = new Padding(3, 3, 3, 18)
        };
        form.Controls.Add(heading, 0, row);
        form.SetColumnSpan(heading, 2);
    }

    private static void AddPathField(TableLayoutPanel form, int row, string label, TextBox target, Action<TextBox> browse)
    {
        TableLayoutPanel path = new() { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 2 };
        path.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        path.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        target.Dock = DockStyle.Fill;
        Button button = SecondaryButton("Browse…");
        button.Click += (_, _) => browse(target);
        path.Controls.Add(target, 0, 0);
        path.Controls.Add(button, 1, 0);
        AddLabeledControl(form, row, label, path);
    }

    private static void AddModeField(TableLayoutPanel form, int row, string label, TextBox target, List<Control> controls)
    {
        Label fieldLabel = AddLabeledControl(form, row, label, target);
        controls.Add(fieldLabel);
        controls.Add(target);
    }

    private static Label AddLabeledControl(TableLayoutPanel form, int row, string text, Control control)
    {
        Label label = new()
        {
            Text = text,
            AutoSize = true,
            Anchor = AnchorStyles.Left,
            ForeColor = Color.FromArgb(45, 55, 72),
            Margin = new Padding(3, 9, 12, 9)
        };
        control.Dock = DockStyle.Fill;
        control.Margin = new Padding(3, 5, 3, 5);
        form.Controls.Add(label, 0, row);
        form.Controls.Add(control, 1, row);
        return label;
    }

    private static void AddFullRow(TableLayoutPanel form, int row, Control control)
    {
        control.Margin = new Padding(3, 7, 3, 7);
        form.Controls.Add(control, 0, row);
        form.SetColumnSpan(control, 2);
    }

    private static Button PrimaryButton(string text) => new()
    {
        Text = text,
        AutoSize = true,
        Padding = new Padding(16, 7, 16, 7),
        BackColor = Blue,
        ForeColor = Color.White,
        FlatStyle = FlatStyle.Flat,
        Font = new Font("Segoe UI Semibold", 9.5f)
    };

    private static Button SecondaryButton(string text) => new()
    {
        Text = text,
        AutoSize = true,
        Padding = new Padding(10, 4, 10, 4),
        BackColor = Color.White,
        ForeColor = Navy,
        FlatStyle = FlatStyle.Flat
    };

    private static string? EmptyToNull(string value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private void ShowWarning(string text) =>
        MessageBox.Show(this, text, "PC Migration Tool", MessageBoxButtons.OK, MessageBoxIcon.Warning);
}
