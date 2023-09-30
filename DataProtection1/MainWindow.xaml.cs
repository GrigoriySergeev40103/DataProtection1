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

		protected char[] _alphabet = { 'x', 'y' };
		protected int _blockLength = 5;

		public Dictionary<string, string> EncryptionMap { get; set; } = new(32);

		public MainWindow()
		{
			string filePath = "cock";

			OpenFileDialog openFileDialog = new()
			{
				Filter = "json files (*.json)|*.json",
				FilterIndex = 2,
				RestoreDirectory = true
			};
			if (openFileDialog.ShowDialog() == true)
			{
				//Get the path of specified file
				filePath = openFileDialog.SafeFileName;
				//SubstitutionEncrypter substitutionEncrypter = new(filePath);
			}
			else
				Close();

			FormEncryptionMap();
			DataContext = this;

			SubstitutionEncrypter substitutionEncrypter = new(new SubstitutionEncrypter.EncrypterData { Map = EncryptionMap, FillerChar = 'x'});
			string str = substitutionEncrypter.Decrypt(substitutionEncrypter.Encrypt("xxxxx"));
			substitutionEncrypter.SaveToFile(filePath);

			InitializeComponent();
		}

		protected void FormEncryptionMap()
		{
			string[] permutations = Util.GetPermutationsWithRept(_alphabet, 5).Select(x => new string(x.ToArray())).ToArray();
			string[] shuffled = (string[])(permutations.Clone());
			Random.Shared.Shuffle(shuffled);

			for (int i = 0; i < permutations.Length; i++)
				EncryptionMap.Add(permutations[i], shuffled[i]);
		}

		protected string Encrypt(string toEncrypt)
		{
			int remainder = toEncrypt.Length % _blockLength;
			string sourceText = remainder switch
			{
				0 => toEncrypt,
				_ => toEncrypt + new string(_alphabet[0], _blockLength - remainder)
			};

			StringBuilder encryptedString = new(sourceText.Length);

			for (int i = 0; i < sourceText.Length; i += _blockLength)
				encryptedString.Append(EncryptionMap[sourceText[i..(i + _blockLength)]]);

			return encryptedString.ToString();
		}

		protected string Decrypt(string toDecrypt)
		{
			int remainder = toDecrypt.Length % _blockLength;
			string encryptedText = remainder switch
			{
				0 => toDecrypt,
				_ => toDecrypt + new string(_alphabet[0], _blockLength - remainder)
			};

			StringBuilder decryptedString = new(encryptedText.Length);

			for (int i = 0; i < encryptedText.Length; i += _blockLength)
			{
				string decrypted = EncryptionMap.First(x => x.Value == encryptedText[i..(i + _blockLength)]).Key;
				decryptedString.Append(decrypted);
			}

			return decryptedString.ToString();
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
			encryptedTextBox.Text = Encrypt(sourceTextInput.Text);
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
			sourceTextInput.Text = Decrypt(encryptedTextBox.Text);
		}
	}
}
