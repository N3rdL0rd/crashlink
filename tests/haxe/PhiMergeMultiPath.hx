class PhiMergeMultiPath {
    static function classify(a:Int, b:Int):Int {
        var result:Int;
        if (a > 10) {
            if (b > 10) {
                result = 1;
            } else if (b > 5) {
                result = 2;
            } else {
                result = 3;
            }
        } else if (a > 5) {
            if (b > 10) {
                result = 4;
            } else {
                result = 5;
            }
        } else {
            result = 6;
        }
        return result * 100 + a - b;
    }

    static function main() {
        var cases = [[15,15],[15,7],[15,2],[7,15],[7,2],[2,2]];
        for (c in cases) {
            trace(classify(c[0], c[1]));
        }
    }
}
