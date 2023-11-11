using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace DataProtection1
{
	internal class DesCfbEncrypter : DesEcbEncrypter
	{
		public struct CfbData
		{
			public int T0 { get; set; }
			public int A { get; set; }
			public int C { get; set; }

			public int KBits { get; set; }
		}

		protected CfbData _cfbData;
		protected ulong _c0;
		protected ulong _c;

		public async static new Task<DesCfbEncrypter> FromFile(string fileName)
		{
			JsonSerializerOptions jsonOptions = new()
			{
				IncludeFields = true
			};

			(EncryptionData, CfbData) desCbcData = JsonSerializer.Deserialize<(EncryptionData, CfbData)>(await File.ReadAllTextAsync(fileName), jsonOptions);
			DesCfbEncrypter result = new(desCbcData.Item1, desCbcData.Item2);

			return result;
		}

		public DesCfbEncrypter(EncryptionData encryptionData, CfbData cbcData) : base(encryptionData)
		{
			_cfbData = cbcData;

			int temp = _cfbData.T0;
			for (int i = 0; i < 8; i++)
			{
				_c0 <<= 8;
				_c0 |= (byte)temp;
				temp = (_cfbData.A * temp + _cfbData.C) % 256;
			}
		}

		public override string Encrypt(string toEncrypt)
		{
			int wholeBytes = _cfbData.KBits / 8;
			int additionalBits = _cfbData.KBits - wholeBytes * 8;

			// * 2 since char is 2 bytes
			Span<byte> strBytes = stackalloc byte[toEncrypt.Length * 2];
			Encoding.Unicode.GetBytes(toEncrypt, strBytes);

			int numOfBlocks = (int)MathF.Ceiling((float)strBytes.Length * 8 / _cfbData.KBits);
			Span<ulong> blocks = stackalloc ulong[numOfBlocks];

			Span<byte> blockVal = stackalloc byte[wholeBytes + 1];
			for (int i = 0; i < numOfBlocks; i++)
			{	
				strBytes[..wholeBytes].CopyTo(blockVal);
				byte toAdd = strBytes[wholeBytes];
				toAdd >>= 8 - additionalBits;
				toAdd <<= 8 - additionalBits;

				blockVal[wholeBytes] = toAdd;

				blocks[i] = MemoryMarshal.Read<ulong>(blockVal);
			}

			StringBuilder result = new(toEncrypt.Length);

			Span<byte> bytes = stackalloc byte[8];
			_c = _c0;
			for (int i = 0; i < toEncrypt.Length; i += 4)
			{
				_c <<= _cfbData.KBits;
				ulong encrypted = ProcessBlock(_c, _keys);
				encrypted >>= 64 - _cfbData.KBits;

				Encoding.Unicode.GetBytes(toEncrypt.AsSpan(i, 4), bytes);
				ulong block = MemoryMarshal.Read<ulong>(bytes);
				block >>= 64 - _cfbData.KBits;
				block ^= _c;

				_c = encrypted;
				MemoryMarshal.Write(bytes, ref encrypted);

				result.Append(Encoding.Unicode.GetString(bytes));
			}

			return result.ToString();
		}

		public override string Decrypt(string toDecrypt)
		{
			int remainder = toDecrypt.Length % 4;
			toDecrypt = remainder switch
			{
				0 => toDecrypt,
				_ => toDecrypt + new string(' ', 4 - remainder)
			};

			StringBuilder result = new(toDecrypt.Length);

			Span<byte> bytes = stackalloc byte[8];
			_c = _c0;
			for (int i = 0; i < toDecrypt.Length; i += 4)
			{
				Encoding.Unicode.GetBytes(toDecrypt.AsSpan(i, 4), bytes);
				ulong block = MemoryMarshal.Read<ulong>(bytes);

				ulong decrypted = ProcessBlock(block, _inverseKeys);
				decrypted ^= _c;
				_c = block;
				MemoryMarshal.Write(bytes, ref decrypted);

				result.Append(Encoding.Unicode.GetString(bytes));
			}

			return result.ToString();
		}

		public override async Task LoadFromFileAsync(string fileName)
		{
			JsonSerializerOptions jsonOptions = new()
			{
				IncludeFields = true
			};

			FileStream jsonStream = File.Open(fileName, FileMode.Open);
			_encryptionData = await JsonSerializer.DeserializeAsync<EncryptionData>(jsonStream, jsonOptions);
		}

		public override async Task SaveToFileAsync(string fileName)
		{
			JsonSerializerOptions jsonOptions = new()
			{
				IncludeFields = true
			};

			string saveContent = JsonSerializer.Serialize((_encryptionData, _cfbData), jsonOptions);

			await File.WriteAllTextAsync(fileName, saveContent);
		}
	}
}
