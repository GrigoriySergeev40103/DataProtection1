using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DataProtection1
{
	internal static class EncrypterKeyGenerator
	{
		// 1 - строка, 2 - столбец
		private static readonly int[][] S = new int[][]
		{           // 0    1    2    3    4    5    6    7    8    9    10   11   12   13   14   15
			new int[]{ 14,  4,   13,  1,   2,   15,  11,  8,   3,   10,  6,   12,  5,   9,   0,   7   }, // 0
			new int[]{ 0,   15,  7,   4,   14,  2,   13,  1,   10,  6,   12,  11,  9,   5,   3,   8   }, // 1
			new int[]{ 4,   1,   14,  8,   13,  6,   2,   11,  15,  12,  9,   7,   3,   10,  5,   0   }, // 2
			new int[]{ 15,  12,  8,   2,   4,   9,   1,   7,   5,   11,  3,   14,  10,  0,   6,   13  }, // 3
			        // 0    1    2    3    4    5    6    7    8    9    10   11   12   13   14   15
			new int[]{ 15,  1 ,  8,   14,  6,   11,  3,   4,   9,   7,   2,   13,  12,  0,   5,   10  }, // 0
			new int[]{ 3,   13,  4,   7,   15,  2,   8,   14,  12,  0,   1,   10,  6,   9,   11,  5   }, // 1
			new int[]{ 0,   14,  7,   11,  10,  4,   13,  1,   5,   8,   12,  6,   9,   3,   2,   15  }, // 2
			new int[]{ 13,  8,   10,  1,   3,   15,  4,   2,   11,  6,   7,   12,  0,   5,   14,  9   }, // 3
			        // 0    1    2    3    4    5    6    7    8    9    10   11   12   13   14   15
			new int[]{ 10,  0,   9,   14,  6,   3,   15,  5,   1,   13,  12,  7,   11,  4,   2,   8   }, // 0
			new int[]{ 13,  7,   0,   9,   3,   4,   6,   10,  2,   8,   5,   14,  12,  11,  15,  1   }, // 1
			new int[]{ 13,  6,   4,   9,   8,   15,  3,   0,   11,  1,   2,   12,  5,   10,  14,  7   }, // 2
			new int[]{ 1,   10,  13,  0,   6,   9,   8,   7,   4,   15,  14,  3,   11,  5,   2,   12  }, // 3
			        // 0    1    2    3    4    5    6    7    8    9    10   11   12   13   14   15
			new int[]{ 7,   13,  14,  3,   0,   6,   9,   10,  1,   2,   8,   5,   11,  12,  4,   15  }, // 0
			new int[]{ 13,  8,   11,  5,   6,   15,  0,   3,   4,   7,   2,   12,  1,   10,  14,  9   }, // 1
			new int[]{ 10,  6,   9,   0,   12,  11,  7,   13,  15,  1,   3,   14,  5,   2,   8,   4   }, // 2
			new int[]{ 3,   15,  0,   6,   10,  1,   13,  8,   9,   4,   5,   11,  12,  7,   2,   14  }, // 3
			        // 0    1    2    3    4    5    6    7    8    9    10   11   12   13   14   15
			new int[]{ 2,   12,  4,   1,   7,   10,  11,  6,   8,   5,   3,   15,  13,  0,   14,  9   }, // 0
			new int[]{ 14,  11,  2,   12,  4,   7,   13,  1,   5,   0,   15,  10,  3,   9,   8,   6   }, // 1
			new int[]{ 4,   2,   1,   11,  10,  13,  7,   8,   15,  9,   12,  5,   6,   3,   0,   14  }, // 2
			new int[]{ 11,  8,   12,  7,   1,   14,  2,   13,  6,   15,  0,   9,   10,  4,   5,   3   }, // 3
			        // 0    1    2    3    4    5    6    7    8    9    10   11   12   13   14   15
			new int[]{ 12,  1,   10,  15,  9,   2,   6,   8,   0,   13,  3,   4,   14,  7,   5,   11  }, // 0
			new int[]{ 10,  15,  4,   2,   7,   12,  9,   5,   6,   1,   13,  14,  0,   11,  3,   8   }, // 1
			new int[]{ 9,   14,  15,  5,   2,   8,   12,  3,   7,   0,   4,   10,  1,   13,  11,  6   }, // 2
			new int[]{ 4,   3,   2,   12,  9,   5,   15,  10,  11,  14,  1,   7,   6,   0,   8,   13  }, // 3
			        // 0    1    2    3    4    5    6    7    8    9    10   11   12   13   14   15
			new int[]{ 4,   11,  2,   14,  15,  0,   8,   13,  3,   12,  9,   7,   5,   10,  6,   1   }, // 0
			new int[]{ 13,  0,   11,  7,   4,   9,   1,   10,  14,  3,   5,   12,  2,   15,  8,   6   }, // 1
			new int[]{ 1,   4,   11,  13,  12,  3,   7,   14,  10,  15,  6,   8,   0,   5,   9,   2   }, // 2
			new int[]{ 6,   11,  13,  8,   1,   4,   10,  7,   9,   5,   0,   15,  14,  2,   3,   12  }, // 3
			        // 0    1    2    3    4    5    6    7    8    9    10   11   12   13   14   15
			new int[]{ 13,  2,   8,   4,   6,   15,  11,  1,   10,  9,   3,   14,  5,   0,   12,  7   }, // 0
			new int[]{ 1,   15,  13,  8,   10,  3,   7 ,  4,   12,  5,   6,   11,  0,   14,  9,   2   }, // 1
			new int[]{ 7,   11,  4,   1,   9,   12,  14,  2,   0,   6,   10,  13,  15,  13,  5,   8   }, // 2
			new int[]{ 2,   1,   14,  7,   4,   10,  8,   13,  5,   12,  9,   0,   3,   5,   5,   11  }, // 3
		};

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

		public static DesEcbEncrypter.EncryptionData GenerateEcbEncrypter()
		{
			DesEcbEncrypter.EncryptionData result = new();
			result.IP = new(64);

			Span<int> shuffledInts = stackalloc int[64];
			for (int i = 0; i < 64; i++)
				shuffledInts[i] = i + 1;
			Random.Shared.Shuffle(shuffledInts);

			for (int i = 0; i < 64; i++)
			{
				result.IP.Add(i + 1, shuffledInts[i]);
			}

			result.InvIP = result.IP.ToDictionary(x => x.Value, x => x.Key);

			result.P = new(32);
			Span<int> shuffledInts32 = shuffledInts[..32];
			for (int i = 0; i < 32; i++)
				shuffledInts32[i] = i + 1;
			Random.Shared.Shuffle(shuffledInts32);

			for (int i = 0; i < 32; i++)
				result.P.Add(i + 1, shuffledInts32[i]);

			result.LSi = new(16);
			for (int i = 0; i < 16; i++)
				result.LSi.Add(i + 1, Random.Shared.Next(1, 3));

			result.Expansion = new Dictionary<int, (int, int?)>()
			{
				{ 1,  ( 2, 48 )    },
				{ 2,  ( 3, null )  },
				{ 3,  ( 4, null )  },
				{ 4,  ( 5, 7 )     },
				{ 5,  ( 6, 8 )     },
				{ 6,  ( 9, null )  },
				{ 7,  ( 10, null )  },
				{ 8,  ( 11, 13 )   },
				{ 9,  ( 12, 14 )   },
				{ 10, ( 15, null ) },
				{ 11, ( 16, null ) },
				{ 12, ( 17, 19 )   },
				{ 13, ( 18, 20 )   },
				{ 14, ( 21, null ) },
				{ 15, ( 22, null ) },
				{ 16, ( 23, 25 )   },
				{ 17, ( 24, 26 )   },
				{ 18, ( 27, null ) },
				{ 19, ( 28, null ) },
				{ 20, ( 29, 31 )   },
				{ 21, ( 30, 32 )   },
				{ 22, ( 33, null ) },
				{ 23, ( 34, null ) },
				{ 24, ( 35, 37 )   },
				{ 25, ( 36, 38 )   },
				{ 26, ( 39, null ) },
				{ 27, ( 40, null ) },
				{ 28, ( 41, 43 )   },
				{ 29, ( 42, 44 )   },
				{ 30, ( 45, null ) },
				{ 31, ( 46, null ) },
				{ 32, ( 1, 47 )    }
			};

			result.PC1 = new(56);
			List<int> PC1Values = new()
			{
				56, 48, 40, 32, 24, 16, 8,  0,  57, 49, 41, 33, 25, 17,
				9,  1,  58, 50, 42, 34, 26, 18, 10, 2,  59, 51, 43, 35,
				62, 54, 46, 38, 30, 22, 14, 6,  61, 53, 45, 37, 29, 21,
				13, 5,  60, 52, 44, 36, 28, 20, 12, 4,  27, 19, 11, 3
			};
			for (int i = 0; i < 56; i++)
				result.PC1.Add(i + 1, PC1Values[i]);

			result.PC2 = new(48);
			List<int> PC2Values = new()
			{
				13, 16, 10, 23, 0,  4,  2,  27, 14, 5,  20, 9,  22, 18, 11, 3,
				25, 7 , 15, 6,  26, 19, 12, 1,  40, 51, 30, 36, 46, 54, 29, 39,
				50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
			};
			for (int i = 0; i < 48; i++)
				result.PC2.Add(i + 1, PC2Values[i]);

			result.S = S;

			return result;
		}
	}
}
