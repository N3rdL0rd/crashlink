class CatchOrder {
    static function risky(x:Int):Int {
        if (x == 0) throw new haxe.Exception("zero");
        if (x == 1) throw "stringy";
        return Std.int(100 / x);
    }
    static function main() {
        for (x in [0, 1, 2]) {
            try {
                Sys.println(risky(x));
            } catch (e:haxe.Exception) {
                Sys.println("Exception: " + e.message);
            } catch (e:Dynamic) {
                Sys.println("Dynamic: " + Std.string(e));
            }
        }
    }
}
