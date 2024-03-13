<?php

class a{
    function a_meth1(){
        while(1==1){
            if(1==1){
                function b_func(){
                    $test = null;
                     //print($taint);
                     if($test){
                        $taint = $_GET['test'];
                     }
                     else{
                        echo system(trim('ls'.$taint));
                     }
                }
             }
        }
    }
    function a_meth2(){
        echo 1;
    }
}
class b extends a{
    function b_meth1(){
        echo "classB\n";
    }

    function a_meth2(){
        echo "classB\n";
        parent::a_meth2();
    }
}

function func1(){
        echo 1;
}

$a = a();
$a.a_meth1();