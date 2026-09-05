function fig_exp3_makespan_boxplot()
%FIG_EXP3_MAKESPAN_BOXPLOT  T_all_isolated (containment makespan) by K.
% Reads exp3_trials.csv. Boxplot per K with raw trial points overlaid (small n,
% so raw points must be visible). Self-contained. No boxplot toolbox needed for
% the raw-point fallback if the Statistics Toolbox 'boxchart' is unavailable.

% ---- STYLE ----
col_pt=[0.031 0.318 0.612]; box_face=[0.776 0.859 0.937];
fsize=11; figsize=[0 0 5.6 4.0];
% ---------------
here=fileparts(mfilename('fullpath'));
T=readtable(fullfile(here,'exp3_trials.csv'));
Ks=[1 2 3 4];
fig=figure('Units','inches','Position',figsize,'Color','w'); ax=axes(fig); hold(ax,'on');
for i=1:numel(Ks)
    v=T.T_all_isolated_s(T.K==Ks(i)); v=v(~isnan(v));
    % simple box (quartiles) drawn manually for portability
    q=quantile(v,[0.25 0.5 0.75]); lo=min(v); hi=max(v);
    w=0.28;
    fill(ax,Ks(i)+[-w w w -w],[q(1) q(1) q(3) q(3)],box_face,'EdgeColor',[0.2 0.3 0.5],'FaceAlpha',0.7);
    plot(ax,Ks(i)+[-w w],[q(2) q(2)],'Color',[0.03 0.19 0.42],'LineWidth',1.6);   % median
    plot(ax,[Ks(i) Ks(i)],[lo q(1)],'Color',[0.2 0.3 0.5]); plot(ax,[Ks(i) Ks(i)],[q(3) hi],'Color',[0.2 0.3 0.5]);
    xs=Ks(i)+((1:numel(v))-numel(v)/2)*0.05;
    scatter(ax,xs,v,26,col_pt,'filled','MarkerEdgeColor','w','LineWidth',0.4);
end
xlabel(ax,'Concurrent compromised xApps K','FontSize',fsize);
ylabel(ax,'T_{all-isolated} (s)','FontSize',fsize);
xticks(ax,Ks); xlim(ax,[0.5 4.5]); ylim(ax,[0 max(T.T_all_isolated_s)*1.12]);
grid(ax,'on'); ax.GridAlpha=0.3; box(ax,'on'); ax.FontSize=fsize-1;
title(ax,'Concurrent-containment makespan (n=6/K; box + raw points)','FontSize',fsize-1);
hold(ax,'off');
exportgraphics(fig,fullfile(here,'exp3_makespan_boxplot.pdf'),'ContentType','vector');
exportgraphics(fig,fullfile(here,'exp3_makespan_boxplot.png'),'Resolution',200); close(fig);
end
