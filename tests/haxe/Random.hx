class Random {
    static function main() {
        var randomNumber = Std.random(10);
        trace("A random number between 0 and 9: " + randomNumber);

        var min = 1;
        var max = 100;
        var rangedRandomNumber = min + Std.random(max - min + 1);
        trace("A random number between " + min + " and " + max + ": " + rangedRandomNumber);

        var randomFloat = Math.random();
        trace("A random float between 0 and 1: " + randomFloat);
    }
}