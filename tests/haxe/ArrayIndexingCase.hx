class ArrayIndexingCase {
    static function sum(a: Array<Int>): Int {
        var total = 0;
        for (i in 0...a.length)
            total += a[i];
        return total;
    }

    static function swap(a: Array<Int>, i: Int, j: Int): Void {
        var tmp = a[i];
        a[i] = a[j];
        a[j] = tmp;
    }

    public static function main(): Void {
        var arr = [1, 2, 3];
        swap(arr, 0, 2);
        var s = sum(arr);
    }
}
