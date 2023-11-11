﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace DataProtection1
{
	internal class DesCbcEncrypter : DesEcbEncrypter
	{
		public struct CbcData
		{
			public int T0 { get; set; }
			public int A { get; set; }
			public int C { get; set; }
		}

		protected CbcData _cbcData;
		protected ulong _c0;
		protected ulong _c;

		public async static new Task<DesCbcEncrypter> FromFile(string fileName)
		{
			JsonSerializerOptions jsonOptions = new()
			{
				IncludeFields = true
			};

			(EncryptionData, CbcData) desCbcData = JsonSerializer.Deserialize<(EncryptionData, CbcData)>(await File.ReadAllTextAsync(fileName), jsonOptions);
			DesCbcEncrypter result = new(desCbcData.Item1, desCbcData.Item2);

			return result;
		}

		public DesCbcEncrypter(EncryptionData encryptionData, CbcData cbcData) : base(encryptionData)
		{
			_cbcData = cbcData;

			int temp = _cbcData.T0;
			for (int i = 0; i < 8; i++)
			{
				_c0 <<= 8;
				_c0 |= (byte)temp;
				temp = (_cbcData.A * temp + _cbcData.C) % 256;
			}
		}

		public override string Encrypt(string toEncrypt)
		{
			int remainder = toEncrypt.Length % 4;
			toEncrypt = remainder switch
			{
				0 => toEncrypt,
				_ => toEncrypt + new string(' ', 4 - remainder)
			};

			StringBuilder result = new(toEncrypt.Length);

			Span<byte> bytes = stackalloc byte[8];
			_c = _c0;
			for (int i = 0; i < toEncrypt.Length; i += 4)
			{
				Encoding.Unicode.GetBytes(toEncrypt.AsSpan(i, 4), bytes);
				ulong block = MemoryMarshal.Read<ulong>(bytes);
				block ^= _c;

				ulong encrypted = ProcessBlock(block, _keys);
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

			string saveContent = JsonSerializer.Serialize((_encryptionData, _cbcData), jsonOptions);

			await File.WriteAllTextAsync(fileName, saveContent);
		}
	}
}
