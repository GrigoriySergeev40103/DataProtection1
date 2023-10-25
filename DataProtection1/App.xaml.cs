using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
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

			GammaEncrypter.EncryptionData encryptionData = new()
			{
				A  = 29,
				C  = 27,
				T0 = 16
			};

			List<char> alphabet = new(256);
            for (int i = 0; i < 256; i++)
				alphabet.Add((char)i);

			GammaEncrypter gammaEncrypter = new(encryptionData);

			RearrangeEncrypter encrypter = RearrangeEncrypter.FromFile(pathToJson).Result;

			var mainWindow = new DataProtection1.MainWindow(encrypter, pathToJson);
			mainWindow.Show();
			mainWindow.Activate();
		}
	}
}
