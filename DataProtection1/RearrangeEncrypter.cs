using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace DataProtection1
{
	internal class RearrangeEncrypter : IEncrypter
	{
		public struct EncrypterData
		{
			public Dictionary<int, int> PosShuffleMap { get; set; }
			public char FillerChar { get; set; }
		}

		protected EncrypterData _encrypterData;
		protected Dictionary<int, int> _reversedShuffleMap;
		protected int _blockLength;
		protected HashSet<char> _alphabet;

		public RearrangeEncrypter(EncrypterData encrypterData, HashSet<char> alphabet)
		{
			_encrypterData = encrypterData;
			_blockLength = _encrypterData.PosShuffleMap.Keys.Count;
			_alphabet = alphabet;
			_reversedShuffleMap = _encrypterData.PosShuffleMap.ToDictionary(x => x.Value, x => x.Key);
		}

		public string Decrypt(string toDecrypt)
		{
			int remainder = toDecrypt.Length % _blockLength;
			string encryptedText = remainder switch
			{
				0 => toDecrypt,
				_ => toDecrypt + new string(_encrypterData.FillerChar, _blockLength - remainder)
			};

			StringBuilder decryptedString = new(encryptedText.Length);

			int blockCount = encryptedText.Length / _blockLength;
			for (int i = 0; i < blockCount; i++)
			{
				for (int j = 0; j < _blockLength; j++)
				{
					int shuffledPos = _reversedShuffleMap[j + 1];
					decryptedString.Append(encryptedText[i * _blockLength + shuffledPos]);
				}
			}

			return decryptedString.ToString();
		}

		public string Encrypt(string toEncrypt)
		{
			int remainder = toEncrypt.Length % _blockLength;
			string sourceText = remainder switch
			{
				0 => toEncrypt,
				_ => toEncrypt + new string(_encrypterData.FillerChar, _blockLength - remainder)
			};

			StringBuilder encryptedString = new(sourceText.Length);

			int blockCount = sourceText.Length / _blockLength;
			for (int i = 0; i < blockCount; i++)
			{
				for (int j = 0; j < _blockLength; j++)
				{
					int shuffledPos = _encrypterData.PosShuffleMap[j + 1];
					encryptedString.Append(sourceText[i * _blockLength + shuffledPos]);
				}
			}

			return encryptedString.ToString();
		}

		public bool IsValidMessage(string message)
		{
			foreach (char c in message)
			{
				if (!_alphabet.Contains(c))
					return false;
			}

			return true;
		}

		public async Task LoadFromFileAsync(string fileName)
		{
			FileStream jsonStream = File.Open(fileName, FileMode.Open);
			_encrypterData = await JsonSerializer.DeserializeAsync<EncrypterData>(jsonStream);
			_blockLength = _encrypterData.PosShuffleMap.Keys.Count;
		}

		public async Task SaveToFileAsync(string fileName)
		{
			JsonSerializerOptions jsonOptions = new()
			{
				WriteIndented = true
			};

			string saveContent = JsonSerializer.Serialize(_encrypterData, jsonOptions);

			await File.WriteAllTextAsync(fileName, saveContent);
		}
	}
}
