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
			public int[] PosShuffleList { get; set; }
			public char FillerChar { get; set; }
		}

		protected EncrypterData _encrypterData;
		protected int[] _reversedShuffle;
		protected int _blockLength;

		public RearrangeEncrypter(EncrypterData encrypterData)
		{
			_encrypterData = encrypterData;
			_blockLength = _encrypterData.PosShuffleList.Length;

			for (int i = 0; i < _encrypterData.PosShuffleList.Length; i++)
				_encrypterData.PosShuffleList[i]--;

			_reversedShuffle = new int[_encrypterData.PosShuffleList.Length];
			for (int i = 0; i < _reversedShuffle.Length; i++)
				_reversedShuffle[_encrypterData.PosShuffleList[i]] = i;
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
					int shuffledPos = _encrypterData.PosShuffleList[j];
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
					int shuffledPos = _encrypterData.PosShuffleList[j];
					encryptedString.Append(sourceText[i * _blockLength + shuffledPos]);
				}
			}

			return encryptedString.ToString();
		}

		public bool IsValidMessage(string message) => true;

		public async Task LoadFromFileAsync(string fileName)
		{
			FileStream jsonStream = File.Open(fileName, FileMode.Open);
			_encrypterData = await JsonSerializer.DeserializeAsync<EncrypterData>(jsonStream);
			_blockLength = _encrypterData.PosShuffleList.Length;
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

		public async static Task<RearrangeEncrypter> FromFile(string fileName)
		{
			EncrypterData encryptionData = JsonSerializer.Deserialize<EncrypterData>(await File.ReadAllTextAsync(fileName));
			RearrangeEncrypter result = new(encryptionData);

			return result;
		}
	}
}
