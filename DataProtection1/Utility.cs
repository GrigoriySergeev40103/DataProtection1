using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DataProtection1
{
	static class RandomExtensions
	{
		public static void Shuffle<T>(this Random rng, Span<T> array)
		{
			int n = array.Length;
			while (n > 1)
			{
				int k = rng.Next(n--);
				(array[k], array[n]) = (array[n], array[k]);
			}
		}
	}

	internal static class Utility
	{
		public static IEnumerable<IEnumerable<T>> GetPermutationsWithRept<T>(IEnumerable<T> list, int length)
		{
			if (length == 1) return list.Select(t => new T[] { t });
			return GetPermutationsWithRept(list, length - 1)
				.SelectMany(t => list,
					(t1, t2) => t1.Concat(new T[] { t2 }));
		}
	}
}
