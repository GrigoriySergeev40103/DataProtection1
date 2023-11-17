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

		protected void DivideIntoKLongs(Span<ulong> destination, string toDivide)
		{
			int bitLength = toDivide.Length * 2 * 8;
			Span<byte> bytes = stackalloc byte[toDivide.Length * 2];
			int blockCount = (bitLength + _cfbData.KBits - 1) / _cfbData.KBits;

			Encoding.Unicode.GetBytes(toDivide.AsSpan(0, toDivide.Length), bytes);

			bool bit;
			int shift = 0;
			int indexByte = bytes.Length - 1;
			for (int i = 0; i < blockCount; i++)
			{
				for (int j = 0; j < _cfbData.KBits; j++)
				{
					destination[i] <<= 1;
					if (indexByte >= 0)
					{
						bit = ((byte)(bytes[indexByte]) & (1ul << 7 - shift)) != 0;
						if (bit)
							destination[i] |= 1ul;
					}

					if (shift == 7)
					{
						shift = 0;
						indexByte--;
					}
					else
						shift++;
				}
				destination[i] <<= 64 - _cfbData.KBits;
			}
		}

		protected string AssembleFromKLongs(Span<ulong> longs)
		{
			int byteCount = longs.Length * _cfbData.KBits / 8;
			bool bit;
			Span<byte> bytes = stackalloc byte[byteCount];
			int countBit = 0;
			int indexByte = byteCount - 1;

			for (int i = 0; i < longs.Length; i++)
			{
				int shift = 0;
				for (int j = 0; j < _cfbData.KBits; j++)
				{
					if (countBit == 8)
					{
						countBit = 1;

						--indexByte;
					}
					else
						++countBit;

					if (indexByte >= 0)
					{
						bytes[indexByte] <<= 1;
						bit = (longs[i] & (1ul << 63 - shift)) != 0;
						if (bit)
							bytes[indexByte] |= 1;
					}

					++shift;
				}

			}

			return Encoding.Unicode.GetString(bytes);
		}

		public override string Encrypt(string toEncrypt)
		{
			int blockCount = ((toEncrypt.Length * 2 * 8) + _cfbData.KBits - 1) / _cfbData.KBits;
			Span<ulong> blocks = stackalloc ulong[blockCount];
			DivideIntoKLongs(blocks, toEncrypt);

			_c = _c0;
			ulong outBlock;
			ulong block;
			bool bit;
			int shift;

			for (int i = 0; i < blocks.Length; i++)
			{
				shift = 63;
				outBlock = 0;

				block = ProcessBlock(_c, _keys);

				for (int j = 0; j < _cfbData.KBits; j++)
				{
					bit = (block & (1ul << 63 - j)) != 0;
					if (bit)
						outBlock |= 1ul << shift;
					shift--;
				}

				outBlock ^= blocks[i];

				for (int j = 0; j < _cfbData.KBits; j++)
				{
					_c <<= 1;
					bit = (outBlock & (1ul << 63 - j)) != 0;
					if (bit)
						_c |= 1ul;
				}

				blocks[i] = outBlock;
			}

			return AssembleFromKLongs(blocks);
		}

		public override string Decrypt(string toDecrypt)
		{
			int blockCount = ((toDecrypt.Length * 2 * 8) + _cfbData.KBits - 1) / _cfbData.KBits;
			Span<ulong> blocks = stackalloc ulong[blockCount];
			DivideIntoKLongs(blocks, toDecrypt);

			_c = _c0;
			ulong outBlock;
			ulong block;
			bool bit;
			int shift;

			for (int i = 0; i < blocks.Length; i++)
			{
				shift = 63;
				outBlock = 0;

				block = ProcessBlock(_c, _keys);

				for (int j = 0; j < _cfbData.KBits; j++)
				{
					bit = (block & (1ul << 63 - j)) != 0;
					if (bit)
						outBlock |= 1ul << shift;
					shift--;
				}

				outBlock ^= blocks[i];

				for (int j = 0; j < _cfbData.KBits; j++)
				{
					_c <<= 1;
					bit = (blocks[i] & (1ul << 63 - j)) != 0;
					if (bit)
						_c |= 1ul;
				}

				blocks[i] = outBlock;
			}

			return AssembleFromKLongs(blocks);
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
