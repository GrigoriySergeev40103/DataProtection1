using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using System.Buffers.Binary;
using System.Windows.Documents;
using System.Runtime.InteropServices;

namespace DataProtection1
{
	internal class DesEcbEncrypter : IEncrypter
	{
		public struct EncryptionData
		{
			public Dictionary<int, int> IP { get; set; }
			public Dictionary<int, int> InvIP { get; set; }
			public Dictionary<int, (int, int?)> Expansion { get; set; }
			public Dictionary<int, int> P { get; set; }
			public Dictionary<int, int> PC1 { get; set; }
			public Dictionary<int, int> PC2 { get; set; }
			public Dictionary<int, int> LSi { get; set; }
			public int[][] S { get; set; }

			public ulong K { get; set; }
		}

		protected EncryptionData _encryptionData;

		public string Decrypt(string toDecrypt)
		{
			throw new NotImplementedException();
		}

		public string Encrypt(string toEncrypt)
		{
			Span<byte> bytes = Encoding.Unicode.GetBytes(toEncrypt);

			ulong block = MemoryMarshal.Read<ulong>(bytes);
			ulong shuffledBlock = 0;

			for (int i = 0; i < _encryptionData.IP.Count; i++)
			{
				bool bit = (block & (1ul << 63 - i)) != 0;
				if (bit)
				{
					int bitPosition = _encryptionData.IP[i + 1] - 1;
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

			ulong concat = r + l;
			ulong shuffledConcat = 0;

			for (int i = 0; i < _encryptionData.InvIP.Count; i++)
			{
				bool bit = (concat & (1ul << 63 - i)) != 0;
				if (bit)
				{
					int bitPosition = _encryptionData.InvIP[i + 1] - 1;
					shuffledConcat |= 1ul << 63 - bitPosition;
				}
			}

			MemoryMarshal.Write(bytes, ref shuffledConcat);

			string result = Encoding.Unicode.GetString(bytes);

			return result;
		}

		public bool IsValidMessage(string message) => true;

		public Task LoadFromFileAsync(string fileName)
		{
			throw new NotImplementedException();
		}

		public Task SaveToFileAsync(string fileName)
		{
			throw new NotImplementedException();
		}

		protected ulong[] FormKeys()
		{
			ulong[] keys = new ulong[16];

			ulong k0 = 0;

			for (int i = 0; i < _encryptionData.PC1.Count; i++)
			{
				bool bit = (_encryptionData.K & (1ul << 63 - i)) != 0;
				if (bit)
				{
					int bitPosition = _encryptionData.PC1[i + 1] - 1;
					k0 |= 1ul << 63 - bitPosition;
				}
			}

			// splitting 56 bits into 2 28 bit sets
			uint l = (uint)((k0 >> 36) << 4);
			uint r = (uint)((k0 << 28) >> 36);

			for (int i = 0; i < 16; i++)
			{
				l <<= _encryptionData.LSi[i + 1];
				r <<= _encryptionData.LSi[i + 1];

				ulong concat = 0;
				concat |= l;
				concat <<= 24;
				concat |= r;
				concat <<= 8;
				ulong shuffledConcat = 0;

				for (int j = 0; j < _encryptionData.PC2.Count; j++)
				{
					bool bit = (concat & (1ul << 63 - j)) != 0;
					if (bit)
					{
						int bitPosition = _encryptionData.PC2[j + 1] - 1;
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

			for (int i = 0; i < _encryptionData.Expansion.Count; i++)
			{
				(int, int?) shufflePoses = _encryptionData.Expansion[i + 1];
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

			Span<byte> s = stackalloc byte[8];
			for (int i = 0; i < 8; i++)
			{
				int shiftBy = 64 - 6 * (i + 1);
				s[i] = (byte)((byte)(expanded >> shiftBy) << 2);
			}
			Span<byte> sRes = stackalloc byte[8];

			byte sK = 0;
			byte sL = 0;
			for (int i = 0; i < 8; i++)
			{
				// Form k
				bool bit = (s[i] & (1 << 0)) != 0;
				if (bit)
					sK |= 1 << 0;
				bit = (s[i] & (1 << 5)) != 0;
				if (bit)
					sK |= 1 << 1;

				// Form l
				bit = (s[i] & (1 << 1)) != 0;
				if (bit)
					sL |= 1 << 0;
				bit = (s[i] & (1 << 2)) != 0;
				if (bit)
					sL |= 1 << 1;
				bit = (s[i] & (1 << 3)) != 0;
				if (bit)
					sL |= 1 << 2;
				bit = (s[i] & (1 << 4)) != 0;
				if (bit)
					sL |= 1 << 3;

				sRes[i] = (byte)_encryptionData.S[sL][sK];
				sRes[i] <<= 4;
			}

			uint sResInt = MemoryMarshal.Read<uint>(sRes);
			uint result = 0;

			for (int i = 0; i < _encryptionData.P.Count; i++)
			{
				bool bit = (sResInt & (1u << 63 - i)) != 0;
				if (bit)
				{
					int bitPosition = _encryptionData.P[i + 1] - 1;
					result |= 1u << 63 - bitPosition;
				}
			}

			return result;
		}
	}
}
