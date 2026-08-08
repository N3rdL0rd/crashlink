class TryLoopContinue {
    static function main() {
        var results = "";
        var i = 0;
        while (i < 6) {
            try {
                if (i == 2 || i == 4) throw "boom" + i;
                results += i + ",";
            } catch (e:String) {
                results += "E(" + e + "),";
            }
            i++;
        }
        Sys.println(results);

        var sum = 0;
        for (j in 0...5) {
            try {
                if (j == 1) throw "skip";
                sum += j;
            } catch (e:String) {
                continue;
            }
        }
        Sys.println(sum);
    }
}
