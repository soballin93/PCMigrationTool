using System.Drawing.Imaging;
using PCMigrationTool.Core.Infrastructure;

namespace PCMigrationTool;

internal sealed class ScreenCaptureService(IAppLogger logger)
{
    public IReadOnlyList<string> CaptureAll(string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (string existing in Directory.EnumerateFiles(destination, "*.png"))
        {
            File.Delete(existing);
        }

        List<string> files = [];
        for (int index = 0; index < Screen.AllScreens.Length; index++)
        {
            Screen screen = Screen.AllScreens[index];
            if (screen.Bounds.Width <= 0 || screen.Bounds.Height <= 0)
            {
                continue;
            }
            using Bitmap bitmap = new(screen.Bounds.Width, screen.Bounds.Height);
            using Graphics graphics = Graphics.FromImage(bitmap);
            graphics.CopyFromScreen(screen.Bounds.Location, Point.Empty, screen.Bounds.Size);
            string name = $"Desktop_{index + 1}.png";
            string path = Path.Combine(destination, name);
            bitmap.Save(path, ImageFormat.Png);
            files.Add(name);
        }
        logger.Info($"Captured {files.Count} desktop screenshot(s).");
        return files;
    }
}
