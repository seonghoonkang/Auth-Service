

$(function(){
	/*
    $('#loginForm').on('submit',function(event){

        event.preventDefault();
        if ($("input[name='username']" ).val() && $("input[name='password']" ).val()) {
            $.blockUI({
                message: $('#loadingSpinner')
            });
            $.ajax({
                url: $('#loginForm').attr('action'),
                type: 'POST',
                data : $('#loginForm').serialize(),
                success: function(response){
                    $.unblockUI();

                    console.log("success", response);
                },
                error: function(error) {
                    $.unblockUI();
                    console.log("error", error);

                    $('<div></div>').dialog({
                        modal: true,
                        title: "BizFlow Authentication",
                        height: 200,
                        width: 350,
                        resizable: false,
                        open: function () {
                            var markup = '<div class="p-break-word">' + error.statusText + '</div>';
                            $(this).html(markup);
                        },
                        buttons: {
                            Ok: function () {
                                $(this).dialog("close");
                            }
                        }
                    });
                }
            });
        } else {
            return false;
        }


    });
*/
});
