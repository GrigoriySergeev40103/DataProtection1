using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DataProtection1
{
	internal static class EncrypterKeyGenerator
	{
		public static RearrangeEncrypter.EncryptionData GenerateShuffleEncrypter(int blockLength, char fillerChar)
		{
			RearrangeEncrypter.EncryptionData encrypterData = new();

			Span<int> positions = stackalloc int[blockLength];
			for (int i = 0; i < blockLength; i++)
				positions[i] = i + 1;

			Span<int> shuffledPoses = stackalloc int[blockLength];
			positions.CopyTo(shuffledPoses);
			Random.Shared.Shuffle(shuffledPoses);

			encrypterData.PosShuffleMap = new();
			for (int i = 0; i < blockLength; i++)
				encrypterData.PosShuffleMap.Add(positions[i], shuffledPoses[i]);

			encrypterData.FillerChar = fillerChar;

			return encrypterData;
		}
	}
}
