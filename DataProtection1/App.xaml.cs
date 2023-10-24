using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;

namespace DataProtection1
{
	/// <summary>
	/// Interaction logic for App.xaml
	/// </summary>
	public partial class App : Application
	{
		private static string? TryGetPathToJsonKey()
		{
			OpenFileDialog openFileDialog = new()
			{
				Filter = "json files (*.json)|*.json",
				FilterIndex = 2,
				RestoreDirectory = true
			};

			//Get path to the chosen file
			if (openFileDialog.ShowDialog() == true)
				return openFileDialog.SafeFileName;

			return null;
		}

		App()
		{
			string? pathToJson = TryGetPathToJsonKey();
			if (pathToJson == null)
			{
				Shutdown();
				return; // return so analyzer is not mad for *possible*(at least I think it's not?) null use of encrypter later
			}

			//HashSet<char> alphabet = new() { 'a', 'b', 'c', 'd', 'e', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
			//RearrangeEncrypter encrypter = new(EncrypterKeyGenerator.GenerateShuffleEncrypter(15, '0'));
			//encrypter.SaveToFileAsync(pathToJson).Wait();
			RearrangeEncrypter encrypter = RearrangeEncrypter.FromFile(pathToJson).Result;

			Stopwatch sw = new();
			sw.Start();
			EncrypterKeyGenerator.SlowGenerateShuffleEncrypter(15, '0');
			sw.Stop();
			long slowElapsed = sw.ElapsedTicks;
			sw.Restart();
			EncrypterKeyGenerator.GenerateShuffleEncrypter(15, '0');
			sw.Stop();
			long fastElapsed = sw.ElapsedTicks;
			File.WriteAllText("test.txt", $"slow:{slowElapsed}\n fast:{fastElapsed}");

			var mainWindow = new DataProtection1.MainWindow(encrypter, pathToJson);
			mainWindow.Show();
			mainWindow.Activate();
		}
	}
}
