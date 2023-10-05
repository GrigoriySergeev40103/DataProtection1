using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace DataProtection1
{
	static class RandomExtensions
	{
		public static void Shuffle<T>(this Random rng, T[] array)
		{
			int n = array.Length;
			while (n > 1)
			{
				int k = rng.Next(n--);
				(array[k], array[n]) = (array[n], array[k]);
			}
		}
	}

	/// <summary>
	/// Interaction logic for MainWindow.xaml
	/// </summary>
	public partial class MainWindow : Window
	{
		public static class Util
		{
			public static IEnumerable<IEnumerable<T>> GetPermutationsWithRept<T>(IEnumerable<T> list, int length)
			{
				if (length == 1) return list.Select(t => new T[] { t });
				return GetPermutationsWithRept(list, length - 1)
					.SelectMany(t => list,
						(t1, t2) => t1.Concat(new T[] { t2 }));
			}
		}

		protected IEncrypter _encrypter;

		private string _path;
		private char[] _alphabet = { 'x', 'y' };

		public MainWindow()
		{
			bool isEncrypterLoaded = LoadEncrypterFileDialog();

			if (!isEncrypterLoaded)
				Close();

			DataContext = this;

			InitializeComponent();
		}

		private void SourceTextChanged(object sender, TextChangedEventArgs e)
		{
			if (shouldIgnore)
			{
				shouldIgnore = false;
				return;
			}

			bool isValid = sourceTextInput.Text.All(c => _alphabet.Contains(c));

			if (!isValid)
			{
				sourceTextInput.BorderThickness = new Thickness(2);
				sourceTextInput.BorderBrush = new SolidColorBrush(Colors.Red);
				return;
			}
			else
			{
				sourceTextInput.BorderThickness = new Thickness(1);
				sourceTextInput.BorderBrush = new SolidColorBrush(Colors.LightGray);
			}

			shouldIgnore = true;
			encryptedTextBox.Text = _encrypter.Encrypt(sourceTextInput.Text);
		}

		protected bool shouldIgnore = false;
		private void EncryptedTextChanged(object sender, TextChangedEventArgs e)
		{
			if (shouldIgnore)
			{
				shouldIgnore = false;
				return;
			}

			bool isValid = encryptedTextBox.Text.All(c => _alphabet.Contains(c));

			if (!isValid)
			{
				encryptedTextBox.BorderThickness = new Thickness(2);
				encryptedTextBox.BorderBrush = new SolidColorBrush(Colors.Red);
				return;
			}
			else
			{
				encryptedTextBox.BorderThickness = new Thickness(1);
				encryptedTextBox.BorderBrush = new SolidColorBrush(Colors.LightGray);
			}

			shouldIgnore = true;
			sourceTextInput.Text = _encrypter.Decrypt(encryptedTextBox.Text);
		}

		private void OnSaveButtonClick(object sender, RoutedEventArgs e)
		{
			_encrypter.SaveToFile(_path);
		}

		private void OnRefreshButtonClick(object sender, RoutedEventArgs e)
		{
			_encrypter.LoadFromFile(_path);
		}

		private void OnOpenButtonClick(object sender, RoutedEventArgs e)
		{
			LoadEncrypterFileDialog();
		}

		private bool LoadEncrypterFileDialog()
		{
			OpenFileDialog openFileDialog = new()
			{
				Filter = "json files (*.json)|*.json",
				FilterIndex = 2,
				RestoreDirectory = true
			};

			if (openFileDialog.ShowDialog() == true)
			{
				//Get the path of specified file
				_path = openFileDialog.SafeFileName;
				_encrypter = new SubstitutionEncrypter(_path);
				return true;
			}

			return false;
		}
	}
}
