using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Input;

namespace DataProtection1
{
	internal class DesOfbEncrypter : DesCfbEncrypter
	{
		public DesOfbEncrypter(EncryptionData encryptionData, CfbData cfbData) : base(encryptionData, cfbData)
		{

		}

		public override string Encrypt(string toEncrypt)
		{
			int blockCount = ((toEncrypt.Length * 2 * 8) + _cfbData.KBits - 1) / _cfbData.KBits;
			Span<ulong> blocks = stackalloc ulong[blockCount];
			DivideIntoKLongs(blocks, toEncrypt);

			_c = _c0;
			ulong outBlock;
			ulong block;
			int shift;

			for (int i = 0; i < blocks.Length; i++)
			{
				shift = 63;
				outBlock = 0;

				block = ProcessBlock(_c, _keys);

				for (int j = 0; j < _cfbData.KBits; j++)
				{
					bool bit = (block & (1ul << 63 - j)) != 0;
					if (bit)
						outBlock |= 1ul << shift;
					shift--;
				}

				for (int j = 0; j < _cfbData.KBits; j++)
				{
					_c <<= 1;
					bool bit = (outBlock & (1ul << 63 - j)) != 0;
					if (bit)
						_c |= 1ul;
				}

				blocks[i] = outBlock ^ blocks[i];
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

				for (int j = 0; j < _cfbData.KBits; j++)
				{
					_c <<= 1;
					bit = (outBlock & (1ul << 63 - j)) != 0;
					if (bit)
						_c |= 1ul;
				}

				blocks[i] = outBlock ^ blocks[i];
			}

			return AssembleFromKLongs(blocks);
		}
	}
}
