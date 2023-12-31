﻿using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;

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
		private readonly string _path;

		public MainWindow(IEncrypter encrypter, string path)
		{
			_encrypter = encrypter;
			_path = path;

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

			bool isMessageValid = _encrypter.IsValidMessage(sourceTextInput.Text);
			if (!isMessageValid)
				return;

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

			bool isMessageValid = _encrypter.IsValidMessage(encryptedTextBox.Text);
			if (!isMessageValid)
				return;

			shouldIgnore = true;
			sourceTextInput.Text = _encrypter.Decrypt(encryptedTextBox.Text);
		}

		private void OnRefreshButtonClick(object sender, RoutedEventArgs e) => _encrypter.LoadFromFileAsync(_path);

		private async void OnOpenButtonClick(object sender, RoutedEventArgs e)
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
				string path = openFileDialog.SafeFileName;
				_encrypter = await SubstitutionEncrypter.FromFile(path);
			}
		}
	}
}
