class BigControlFlow {
    public static function main() {
        var x = 10;
        var result = 0.0;
        if (x > 5) {
            result = x * 2;
        } else {
            result = x + 2;
        }

        var y = 2.0;
        switch (y) {
            case 0:
                result = y + 10;
            case 1:
                result = y * 10;
            case 2:
                result = y - 10;
            default:
                result = y / 10;
        }

        for (i in 0...5) {
            result += i * 2;
        }

        var z = 0;
        while (z < 5) {
            result += z + 3;
            z++;
        }

        var w = 0;
        do {
            result += w - 3;
            w++;
        } while (w < 5);

        try {
            var a = 10 / 0;
        } catch (e:Dynamic) {
            result = -1;
        }

        result += factorial(5);

        for (i in 0...3) {
            if (i % 2 == 0) {
                result += i * 5;
            } else {
                result -= i * 5;
            }
        }
    }

    static function factorial(n:Int):Int {
        if (n <= 1) return 1;
        return n * factorial(n - 1);
    }
}