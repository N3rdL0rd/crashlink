class LabeledBreakSwitchTry {
    static function run(mode:Int):String {
        var log = "";
        var stop = false;
        while (!stop) {
            var i = 0;
            while (i < 5 && !stop) {
                try {
                    switch (mode) {
                        case 0:
                            if (i == 2) { stop = true; continue; }
                            log += "a" + i;
                        case 1:
                            if (i == 3) {
                                mode = 2;
                                continue;
                            }
                            log += "b" + i;
                        default:
                            if (i == 1) throw "boom";
                            log += "c" + i;
                    }
                } catch (e:Dynamic) {
                    log += "!" + e;
                    i++;
                    continue;
                }
                i++;
            }
            if (!stop) stop = true;
        }
        return log;
    }

    static function main() {
        trace(run(0));
        trace(run(1));
        trace(run(2));
    }
}
