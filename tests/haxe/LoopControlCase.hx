class LoopControlCase {
    static function sumUntilNegative(arr: Array<Int>): Int {
        var total = 0;
        var i = 0;
        while (i < arr.length) {
            if (arr[i] < 0)
                return total;
            total += arr[i];
            i++;
        }
        return total;
    }

    static function findLastPositive(arr: Array<Int>): Int {
        var i = arr.length - 1;
        while (i >= 0) {
            if (arr[i] > 0)
                return arr[i];
            i--;
        }
        return -1;
    }

    public static function main(): Void {
        var a = [-1, 2, -3, 4];
        var s = sumUntilNegative(a);
        var l = findLastPositive(a);
    }
}
