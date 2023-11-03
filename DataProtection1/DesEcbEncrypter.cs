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
		protected ulong[] _keys;
		protected ulong[] _inverseKeys;

		public DesEcbEncrypter(EncryptionData encryptionData)
		{
			_encryptionData = encryptionData;
			_keys = FormKeys();
			_inverseKeys = _keys.Reverse().ToArray();
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

			for (int i = 0; i < toEncrypt.Length; i += 4)
			{
				byte[] bytes = Encoding.Unicode.GetBytes(toEncrypt.Substring(i, 4));
				ulong block = MemoryMarshal.Read<ulong>(bytes);
				result.Append(ProcessBlock(block, _keys));
			}

			return result.ToString();
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
				result.Append(ProcessBlock(block, _inverseKeys));
			}

			return result.ToString();
		}

		protected string ProcessBlock(ulong block, ulong[] keys)
		{
			ulong shuffledBlock = 0;

			// Correct
			for (int i = 0; i < _encryptionData.IP.Length; i++)
			{
				bool bit = (block & (1ul << 63 - i)) != 0;
				if (bit)
				{
					int bitPosition = _encryptionData.IP[i] - 1;
					shuffledBlock |= 1ul << 63 - bitPosition;
				}
			}

			// Correct
			uint l = (uint)(shuffledBlock >> 32);
			uint r = (uint)(shuffledBlock & uint.MaxValue);

			// CORRECT
			for (int i = 0; i < 16; i++)
			{
				uint res = l ^ F(r, keys[i]);
				l = res;
				if (i != 15)
					(l, r) = (r, l);

				//uint oldR = r;
				//r = F(r, keys[i]);
				//uint oldL = l;
				//l = oldR;
				//r ^= oldL;
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

		// CORRECT
		protected ulong[] FormKeys()
		{
			ulong[] keys = new ulong[16];

			ulong k0 = 0;

			// Correct for sure
			for (int i = 0; i < _encryptionData.PC1.Length; i++)
			{
				bool bit = (_encryptionData.K & (1ul << 64 - _encryptionData.PC1[i])) != 0;
				if (bit)
				{
					int bitPosition = i;
					k0 |= 1ul << 63 - bitPosition;
				}
			}

			// Correct
			// splitting 56 bits into 2 28 bit sets
			uint l = (uint)((k0 >> 36) << 4);
			uint r = (uint)((k0 << 28) >> 32);

			for (int i = 0; i < 16; i++)
			{
				// CORRECT
				uint t = l >> (32 - _encryptionData.LSi[i]);
				t <<= 4;
				l = l << _encryptionData.LSi[i] | t;

				t = r >> (32 - _encryptionData.LSi[i]);
				t <<= 4;
				r = r << _encryptionData.LSi[i] | t;

				// CORRECT
				ulong longL = (ulong)l << 32;
				ulong longR = ((ulong)r) << 4;
				ulong concat = longL | longR;
				ulong shuffledConcat = 0;

				// CORRECT
				for (int j = 0; j < _encryptionData.PC2.Length; j++)
				{
					bool bit = (concat & (1ul << 64 - _encryptionData.PC2[j])) != 0;
					if (bit)
					{
						int bitPosition = j;
						int shiftBy = 63 - bitPosition;
						shuffledConcat |= 1ul << shiftBy;
					}
				}

				keys[i] = shuffledConcat;
			}

			return keys;
		}

		protected uint F(uint r, ulong k)
		{
			ulong expanded = 0;

			// Also correct
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

			expanded ^= k; // CORRECT

			//CORRECT
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

				sK >>= 6;

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

				// CORRECT
				sRes[i] = (byte)_encryptionData.S[sK + i * 4][sL];
				sRes[i] <<= 4;
			}

			// CORRECT BUT TO REFACTOR
			uint sResInt = 0;
			uint toConcat = sRes[0];
			int shiftBys = 32 - 8;
			sResInt |= (toConcat << shiftBys);

			for (int i = 1; i < 8; i++)
			{
				toConcat = sRes[i];
				shiftBys = 24 - (i * 4);
				sResInt |= (toConcat << shiftBys);
			}

			toConcat = sRes[7];
			toConcat >>= 4;
			sResInt |= (toConcat << 0);

			uint result = 0;

			for (int j = 0; j < _encryptionData.P.Length; j++)
			{
				bool bit = (sResInt & (1ul << 32 - _encryptionData.P[j])) != 0;
				if (bit)
				{
					int bitPosition = j;
					int shiftBy = 31 - bitPosition;
					result |= 1u << shiftBy;
				}
			}

			return result;
		}
	}
}
