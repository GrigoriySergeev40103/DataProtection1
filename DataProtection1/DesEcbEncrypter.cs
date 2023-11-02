using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using System.Buffers.Binary;
using System.Windows.Documents;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Xml;
using System.Text.Json;
using System.IO;

namespace DataProtection1
{
	internal class DesEcbEncrypter : IEncrypter
	{
		public struct EncryptionData
		{
			public int[] IP { get; set; }
			public int[] InvIP { get; set; }
			public (int, int?)[] Expansion { get; set; }
			public int[] P { get; set; }
			public int[] PC1 { get; set; }
			public int[] PC2 { get; set; }
			public int[] LSi { get; set; }
			public int[][] S { get; set; }

			public ulong K { get; set; }
		}

		protected EncryptionData _encryptionData;

		public DesEcbEncrypter(EncryptionData encryptionData)
		{
			_encryptionData = encryptionData;
		}

		public string Decrypt(string toDecrypt)
		{
			int remainder = toDecrypt.Length % 4;
			toDecrypt = remainder switch
			{
				0 => toDecrypt,
				_ => toDecrypt + new string(' ', 4 - remainder)
			};

			StringBuilder result = new(toDecrypt.Length);

			for (int i = 0; i < toDecrypt.Length; i += 4)
			{
				byte[] bytes = Encoding.Unicode.GetBytes(toDecrypt.Substring(i, 4));
				ulong block = MemoryMarshal.Read<ulong>(bytes);
				result.Append(DecryptBlock(block));
			}

			return result.ToString();
		}

		protected string EncryptBlock(ulong block)
		{
			ulong shuffledBlock = 0;

			for (int i = 0; i < _encryptionData.IP.Length; i++)
			{
				bool bit = (block & (1ul << 63 - i)) != 0;
				if (bit)
				{
					int bitPosition = _encryptionData.IP[i] - 1;
					shuffledBlock |= 1ul << 63 - bitPosition;
				}
			}

			uint l = (uint)(shuffledBlock >> 32);
			uint r = (uint)(shuffledBlock & uint.MaxValue);
			ulong[] keys = FormKeys();

			for (int i = 0; i < 16; i++)
			{
				r = F(r, keys[i]);
				uint oldL = l;
				l = r;
				r ^= oldL;
			}

			ulong longL = (ulong)l << 32;
			ulong longR = r;
			ulong concat = longL | longR;
			ulong shuffledConcat = 0;

			for (int i = 0; i < _encryptionData.InvIP.Length; i++)
			{
				bool bit = (concat & (1ul << 63 - i)) != 0;
				if (bit)
				{
					int bitPosition = _encryptionData.InvIP[i] - 1;
					shuffledConcat |= 1ul << 63 - bitPosition;
				}
			}

			Span<byte> bytes = stackalloc byte[8];

			MemoryMarshal.Write(bytes, ref shuffledConcat);

			string result = Encoding.Unicode.GetString(bytes);

			return result;
		}

		protected string DecryptBlock(ulong block)
		{
			ulong shuffledBlock = 0;

			for (int i = 0; i < _encryptionData.InvIP.Length; i++)
			{
				bool bit = (block & (1ul << 63 - i)) != 0;
				if (bit)
				{
					int bitPosition = _encryptionData.InvIP[i] - 1;
					shuffledBlock |= 1ul << 63 - bitPosition;
				}
			}

			uint l = (uint)(shuffledBlock >> 32);
			uint r = (uint)(shuffledBlock & uint.MaxValue);
			ulong[] keys = FormKeys();

			for (int i = 0; i < 16; i++)
			{
				uint oldR = r;
				r = l;
				l = F(r, keys[15 - i]);
				l ^= oldR;
			}

			ulong longL = (ulong)l << 32;
			ulong longR = r;
			ulong concat = longL | longR;
			ulong shuffledConcat = 0;

			for (int i = 0; i < _encryptionData.IP.Length; i++)
			{
				bool bit = (concat & (1ul << 63 - i)) != 0;
				if (bit)
				{
					int bitPosition = _encryptionData.IP[i] - 1;
					shuffledConcat |= 1ul << 63 - bitPosition;
				}
			}

			Span<byte> bytes = stackalloc byte[8];

			MemoryMarshal.Write(bytes, ref shuffledConcat);

			string result = Encoding.Unicode.GetString(bytes);

			return result;
		}

		public string Encrypt(string toEncrypt)
		{
			int remainder = toEncrypt.Length % 4;
			toEncrypt = remainder switch
			{
				0 => toEncrypt,
				_ => toEncrypt + new string(' ', 4 - remainder)
			};

			StringBuilder result = new(toEncrypt.Length);

			for (int i = 0; i < toEncrypt.Length; i +=4)
			{
				byte[] bytes = Encoding.Unicode.GetBytes(toEncrypt.Substring(i, 4));
				ulong block = MemoryMarshal.Read<ulong>(bytes);
				result.Append(EncryptBlock(block));
			}

			return result.ToString();
		}

		public bool IsValidMessage(string message) => true;

		public async Task LoadFromFileAsync(string fileName)
		{
			FileStream jsonStream = File.Open(fileName, FileMode.Open);
			_encryptionData = await JsonSerializer.DeserializeAsync<EncryptionData>(jsonStream);
		}

		public async Task SaveToFileAsync(string fileName)
		{
			JsonSerializerOptions jsonOptions = new()
			{
				WriteIndented = true
			};

			string saveContent = JsonSerializer.Serialize(_encryptionData, jsonOptions);

			await File.WriteAllTextAsync(fileName, saveContent);
		}

		protected ulong[] FormKeys()
		{
			ulong[] keys = new ulong[16];

			ulong k0 = 0;

			for (int i = 0; i < _encryptionData.PC1.Length; i++)
			{
				bool bit = (_encryptionData.K & (1ul << 63 - i)) != 0;
				if (bit)
				{
					int bitPosition = _encryptionData.PC1[i] - 1;
					k0 |= 1ul << 63 - bitPosition;
				}
			}

			// Correct
			// splitting 56 bits into 2 28 bit sets
			uint l = (uint)((k0 >> 36) << 4);
			uint r = (uint)((k0 << 28) >> 32);

			for (int i = 0; i < 16; i++)
			{
				l <<= _encryptionData.LSi[i];
				r <<= _encryptionData.LSi[i];

				ulong longL = (ulong)l << 32;
				ulong longR = r;
				ulong concat = longL | longR;
				ulong shuffledConcat = 0;

				for (int j = 0; j < _encryptionData.PC2.Length; j++)
				{
					bool bit = (concat & (1ul << 63 - j)) != 0;
					if (bit)
					{
						int bitPosition = _encryptionData.PC2[j] - 1;
						shuffledConcat |= 1ul << 63 - bitPosition;
					}
				}

				keys[i] = shuffledConcat;
			}

			return keys;
		}

		protected uint F(uint r, ulong k)
		{
			ulong expanded = 0;

			for (int i = 0; i < _encryptionData.Expansion.Length; i++)
			{
				(int, int?) shufflePoses = _encryptionData.Expansion[i];
				int bitPosition = shufflePoses.Item1 - 1;
				bool bit = (r & (1 << 31 - i)) != 0;
				if (bit)
				{
					expanded |= 1ul << 63 - bitPosition;
					if (shufflePoses.Item2 != null)
					{
						int secondBitPos = shufflePoses.Item2.Value - 1;
						expanded |= 1ul << 63 - secondBitPos;
					}
				}
			}

			expanded ^= k;

			// PROBLEM(INCORRECT ALGO)
			Span<byte> s = stackalloc byte[8];
			for (int i = 0; i < 8; i++)
			{
				int shiftBy = 64 - 6 * (i + 1);
				s[i] = (byte)(((byte)(expanded >> shiftBy)) << 2);
			}
			Span<byte> sRes = stackalloc byte[8];

			for (int i = 0; i < 8; i++)
			{
				byte sK = 0;
				byte sL = 0;

				// Form k
				bool bit = (s[i] & (1 << 7)) != 0;
				if (bit)
					sK |= 1 << 7;
				bit = (s[i] & (1 << 7 - 5)) != 0;
				if (bit)
					sK |= 1 << 6;

				sK >>= 4;

				// Form l
				bit = (s[i] & (1 << 7 - 1)) != 0;
				if (bit)
					sL |= 1 << 7;
				bit = (s[i] & (1 << 7 - 2)) != 0;
				if (bit)
					sL |= 1 << 6;
				bit = (s[i] & (1 << 7 - 3)) != 0;
				if (bit)
					sL |= 1 << 5;
				bit = (s[i] & (1 << 7 - 4)) != 0;
				if (bit)
					sL |= 1 << 4;

				sL >>= 4;

				sRes[i] = (byte)_encryptionData.S[sL][sK];
				sRes[i] <<= 4;
			}

			uint sResInt = MemoryMarshal.Read<uint>(sRes);
			uint result = 0;

			for (int i = 0; i < _encryptionData.P.Length; i++)
			{
				bool bit = (sResInt & (1u << 63 - i)) != 0;
				if (bit)
				{
					int bitPosition = _encryptionData.P[i] - 1;
					result |= 1u << 63 - bitPosition;
				}
			}

			return result;
		}
	}
}
