using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DataProtection1
{
	internal static class EncrypterKeyGenerator
	{
		public static RearrangeEncrypter.EncrypterData GenerateShuffleEncrypter(int blockLength, char fillerChar)
		{
			RearrangeEncrypter.EncrypterData encrypterData = new();

			Span<int> positions = stackalloc int[blockLength];
			for (int i = 0; i < blockLength; i++)
				positions[i] = i + 1;

			Random.Shared.Shuffle(positions);

			encrypterData.PosShuffleList = new int[blockLength];
			for (int i = 0; i < blockLength; i++)
				encrypterData.PosShuffleList[i] = positions[i];

			encrypterData.FillerChar = fillerChar;

			return encrypterData;
		}
	}
}
