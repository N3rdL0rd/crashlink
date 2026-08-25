class WhileSideEffectCond {
    static var queue:Array<Int> = [1, 2, 3];
    static var calls:Int = 0;

    static function pop():Null<Int> {
        calls++;
        if (queue.length == 0) return null;
        return queue.shift();
    }

    static function main() {
        var v;
        while ((v = pop()) != null) {
            Sys.println("got:" + v);
        }
        Sys.println("calls:" + calls);
    }
}
