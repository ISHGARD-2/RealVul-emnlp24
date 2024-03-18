<?php
include "v.php";
class a{
    var $a_arg1 = '123';
    public function a_meth1(){
        while(1==1){
            if(1==1){
                function a_meth1_func1(){
                    return "test";

                }
                $test = null;
                //print($taint);
                if($test){
                    $taint = $_GET['test'];
                }
                else if($_GET['test']){
                    $taint = 0;
                }
                else if($_POST['test']){
                    $taint = 0;
                }
                else{
                    // echo system(trim('ls'.$taint));
                }
            }
        }
    }
    private function a_meth2(){
        echo 1;
    }
}
class b extends a{
    function b_meth1(){
        //echo "classB\n";
    }

    function a_meth2(){
        //echo "classB\n";
        parent::a_meth2();
        return "12";
    }
}
echo "123";
function func1(&$func1_arg1){
    //echo 1;
    return $_GET["test"];
}

echo func1(
"123");
$a = new a();
$bb = $a->a_meth1();
echo $a->a_arg1;
new b();
func1("123"."qwe".$a->a_meth1());

