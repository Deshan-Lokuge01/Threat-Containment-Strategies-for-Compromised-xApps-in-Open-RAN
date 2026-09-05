function fig_exp1_resource()
%FIG_EXP1_RESOURCE  Detector resource cost vs N: CPU cores and RSS memory.
% Reads exp1_detector_scaling.csv. Produces TWO separate figures (not a dual
% axis): N vs CPU cores, and N vs RSS (MiB). Self-contained.

% ---- STYLE ----
col_cpu=[0.031 0.318 0.612]; col_mem=[0.902 0.333 0.051];
lw=1.8; ms=6; fsize=11; figsize=[0 0 5.6 3.6];
% ---------------
here=fileparts(mfilename('fullpath'));
T=readtable(fullfile(here,'exp1_detector_scaling.csv'));

f1=figure('Units','inches','Position',figsize,'Color','w'); a=axes(f1); hold(a,'on');
plot(a,T.N_contexts,T.cpu_cores,'-o','Color',col_cpu,'LineWidth',lw,'MarkerFaceColor',col_cpu,'MarkerSize',ms);
xlabel(a,'Independent detector contexts N','FontSize',fsize); ylabel(a,'Detector CPU (cores)','FontSize',fsize);
xticks(a,T.N_contexts); grid(a,'on'); a.GridAlpha=0.25; box(a,'on'); a.FontSize=fsize-1;
title(a,'Detector CPU vs number of contexts','FontSize',fsize-1); hold(a,'off');
exportgraphics(f1,fullfile(here,'exp1_detector_cpu.pdf'),'ContentType','vector');
exportgraphics(f1,fullfile(here,'exp1_detector_cpu.png'),'Resolution',200); close(f1);

f2=figure('Units','inches','Position',figsize,'Color','w'); a=axes(f2); hold(a,'on');
plot(a,T.N_contexts,T.rss_mib,'-s','Color',col_mem,'LineWidth',lw,'MarkerFaceColor',col_mem,'MarkerSize',ms);
xlabel(a,'Independent detector contexts N','FontSize',fsize); ylabel(a,'Detector RSS (MiB)','FontSize',fsize);
xticks(a,T.N_contexts); grid(a,'on'); a.GridAlpha=0.25; box(a,'on'); a.FontSize=fsize-1;
title(a,'Detector memory vs number of contexts','FontSize',fsize-1); hold(a,'off');
exportgraphics(f2,fullfile(here,'exp1_detector_rss.pdf'),'ContentType','vector');
exportgraphics(f2,fullfile(here,'exp1_detector_rss.png'),'Resolution',200); close(f2);
end
