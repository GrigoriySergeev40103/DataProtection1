﻿using System;

namespace DataProtection1
{
	internal static class EncrypterKeyGenerator
	{
		private static readonly int[][] S = new int[][]
		{
			new int [] {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
			new int [] {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
			new int [] {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
			new int [] {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
			new int [] {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
			new int [] {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
			new int [] {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
			new int [] {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},

			new int [] {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
			new int [] {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
			new int [] {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
			new int [] {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},

			new int [] {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
			new int [] {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
			new int [] {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
			new int [] {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},

			new int [] {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
			new int [] {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
			new int [] {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
			new int [] {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},

			new int [] {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
			new int [] {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
			new int [] {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
			new int [] {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},

			new int [] {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
			new int [] {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
			new int [] {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
			new int [] {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},

			new int [] {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
			new int [] {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
			new int [] {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
			new int [] {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
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

			result.IP = new int[64]
			{
				40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
				38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
				36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
				34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25
			};

			result.InvIP = new int[64]
			{
				58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
				62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
				57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
				61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
			};

			result.P = new int[32]
			{
				16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
				2,  8, 24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25
			};

			result.LSi = new int[16]
			{
				1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
			};

			result.Expansion = new (int, int?)[32]
			{
				(2, 48 ),
				(3, null),
				(4, null),
				(5, 7),
				(6, 8),
				(9, null),
				(10, null),
				(11, 13),
				(12, 14),
				(15, null),
				(16, null),
				(17, 19),
				(18, 20),
				(21, null),
				(22, null),
				(23, 25),
				(24, 26),
				(27, null),
				(28, null),
				(29, 31),
				(30, 32),
				(33, null),
				(34, null),
				(35, 37),
				(36, 38),
				(39, null),
				(40, null),
				(41, 43),
				(42, 44),
				(45, null),
				(46, null),
				(1, 47)
			};

			result.PC1 = new int[56]
			{
				57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34, 26, 18,
				10,  2, 59, 51, 43, 35, 27, 19, 11, 3,  60, 52, 44, 36,
				63, 55, 47, 39, 31, 23, 15, 7,  62, 54, 46, 38, 30, 22,
				14,  6, 61, 53, 45, 37, 29, 21, 13, 5,  28, 20, 12,  4
			};

			result.PC2 = new int[48]
			{
				14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10,  23, 19, 12, 4,
				26, 8 , 16, 7,  27, 20, 13, 2,  41, 52, 31, 37, 47, 55, 30, 40,
				51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
			};

			result.S = S;

			//result.K = (ulong)Random.Shared.Next(1, int.MaxValue) + (ulong)Random.Shared.Next(1, int.MaxValue);
			result.K = 0xAABB09182736CCDD;

			return result;
		}

		public static (DesCbcEncrypter.EncryptionData, DesCbcEncrypter.CbcData) GenerateCbcEncrypter()
		{
			(DesCbcEncrypter.EncryptionData, DesCbcEncrypter.CbcData) result = new();

			result.Item1.IP = new int[64]
			{
				40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
				38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
				36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
				34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25
			};

			result.Item1.InvIP = new int[64]
			{
				58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
				62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
				57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
				61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
			};

			result.Item1.P = new int[32]
			{
				16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
				2,  8, 24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25
			};

			result.Item1.LSi = new int[16]
			{
				1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
			};

			result.Item1.Expansion = new (int, int?)[32]
			{
				(2, 48 ),
				(3, null),
				(4, null),
				(5, 7),
				(6, 8),
				(9, null),
				(10, null),
				(11, 13),
				(12, 14),
				(15, null),
				(16, null),
				(17, 19),
				(18, 20),
				(21, null),
				(22, null),
				(23, 25),
				(24, 26),
				(27, null),
				(28, null),
				(29, 31),
				(30, 32),
				(33, null),
				(34, null),
				(35, 37),
				(36, 38),
				(39, null),
				(40, null),
				(41, 43),
				(42, 44),
				(45, null),
				(46, null),
				(1, 47)
			};

			result.Item1.PC1 = new int[56]
			{
				57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34, 26, 18,
				10,  2, 59, 51, 43, 35, 27, 19, 11, 3,  60, 52, 44, 36,
				63, 55, 47, 39, 31, 23, 15, 7,  62, 54, 46, 38, 30, 22,
				14,  6, 61, 53, 45, 37, 29, 21, 13, 5,  28, 20, 12,  4
			};

			result.Item1.PC2 = new int[48]
			{
				14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10,  23, 19, 12, 4,
				26, 8 , 16, 7,  27, 20, 13, 2,  41, 52, 31, 37, 47, 55, 30, 40,
				51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
			};

			result.Item1.S = S;

			//result.K = (ulong)Random.Shared.Next(1, int.MaxValue) + (ulong)Random.Shared.Next(1, int.MaxValue);
			result.Item1.K = 0xAABB09182736CCDD;

			result.Item2.A = 33;
			result.Item2.C = 23;
			result.Item2.T0 = 21;

			return result;
		}
	}
}
