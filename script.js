const API="";

document
.getElementById("sendPost")
.onclick=async()=>{

const text=document
.getElementById("postText")
.value;

if(text==="") return;

await fetch(API+"/post",{

method:"POST",

headers:{

"Content-Type":"application/json"

},

body:JSON.stringify({

text

})

});

document
.getElementById("postText")
.value="";

alert("ارسال شد");

};
