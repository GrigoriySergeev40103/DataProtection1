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
		private static SubstitutionEncrypter? TryLoadEncrypterFileDialog(out string path)
		{
			OpenFileDialog openFileDialog = new()
			{
				Filter = "json files (*.json)|*.json",
				FilterIndex = 2,
				RestoreDirectory = true
			};

			if (openFileDialog.ShowDialog() == true)
			{
				//Get path to the chosen file
				path = openFileDialog.SafeFileName;
				return SubstitutionEncrypter.FromFile(path).Result;
			}

			path = string.Empty;
			return null;
		}

		App()
		{
			SubstitutionEncrypter? encrypter = TryLoadEncrypterFileDialog(out string path);
			if (encrypter == null)
				return;

			var mainWindow = new DataProtection1.MainWindow(encrypter, path);
			mainWindow.Show();
			mainWindow.Activate();
		}
	}
}
