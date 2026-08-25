class StaticClosureArrayAssign {
    public static var handlers:Array<Int->Int> = new Array();

    public static function register():Void {
        handlers.push(function(x:Int):Int return x + 1);
        handlers.push(function(x:Int):Int return x * 2);
    }

    public static function main():Void {
        register();
        var total = 0;
        for (h in handlers) {
            total += h(10);
        }
        trace(total);
        trace(handlers[0](5));
        trace(handlers[1](5));
    }
}
